from xcore import need_input_pdf_bytes
from xlog import Logger

logger = Logger("xref")

TYPE_SAFE = True

MODE_XREF_START = 0
MODE_BYTE_INDEX = 1
MODE_MAGIC = 2
MODE_TYPE = 3
MODE_TRAILER_FOUND = 4

def get_xrefs(input, max_xrefs=1, strict=False):
    bytes_pdf = need_input_pdf_bytes(input, "get_xrefs")

    xrefs = []

    length = len(bytes_pdf)
    count = 0
    offset = length-1
    while 0 < offset and count < max_xrefs:
        indicator = ''
        try:
            indicator = bytes_pdf[offset:offset+10].decode("ascii")
        except BaseException as ex:
            prefix = "[get_xrefs]["+str(offset)+":"+str(offset+10)+"]"
            logger.debug(prefix+" error while decode as ascii\n"+
                         "[DEBUG]" + prefix + " " + str(ex))

        if indicator == "startxref\n":
            xref_offset = offset + 10

            saved_offset = []
            while length > xref_offset:
                byte = bytes_pdf[xref_offset]
                if byte is not None and bytes([byte]).decode("ascii") == "\n":
                    break
                saved_offset.append(byte)
                xref_offset += 1
            try:
                int_saved_offset = int(bytes(saved_offset))
                xrefs.append(get_xref(bytes_pdf, xRefIndicator(offset, xref_offset, int_saved_offset), strict=strict))
                count += 1
            except BaseException as ex:
                logger.error("[get_xref][x][unexpected] "+str(ex))
        offset -= 1

    return xrefs

def get_ref_from_lists(index, magic, typ):
    str_type = bytes(typ).decode("ascii")
    return Ref(
        int(bytes(index)),
        bytes(magic),
        str_type
    )

def get_xref(input, indicator, strict=False):
    if not isinstance(indicator, xRefIndicator):
        logger.error("[get_xref] indicator needs to be xRefIndicator", throw=TYPE_SAFE)
    offset = indicator.offset
    bytes_pdf = need_input_pdf_bytes(input, "get_xref")

    part = ''
    index = 0
    last = 'None'
    got_xref_meta = False
    xref = xRef(offset, indicator)

    MODE = MODE_XREF_START
    current_index = None
    current_magic = None
    current_type = None

    while True:
        prefix = "[get_xref][" + str(index) + "]"
        try:
            byte = bytes_pdf[offset]

            char = None
            if strict:
                char = bytes([byte]).decode("ascii")
            else:
                try:
                    char = bytes([byte]).decode("ascii")
                except BaseException as ex:
                    logger.warn(prefix+"[decode] "+str(ex))

            if char == '\n':
                if MODE == MODE_XREF_START:
                    if not part == 'xref':
                        msg = prefix+"[xref_start_finish] missing start xref indicator is not \"xref\""
                        if not strict:
                            logger.warn(msg)
                        else:
                            logger.error(msg, throw=True)
                elif current_index is not None and current_magic is not None and current_type is not None:
                    last = get_ref_from_lists(current_index, current_magic, current_type)
                    xref.add(last)
                else:
                    try:
                        if bytes(current_index).decode('ascii') == "trailer":
                            MODE = MODE_TRAILER_FOUND
                            break
                    except BaseException as ex:
                        explict_prefix = prefix+"[trailer_check]"
                        logger.debug(explict_prefix + " error while decode index as ascii and compare to \"trailer\"\n" +
                                     "[DEBUG]" + explict_prefix + " " + str(ex))

                    if not got_xref_meta:
                        try:
                            meta_size = int(bytes(current_magic))
                            meta_magic = bytes(current_index)
                            xref_meta = xRefMeta(meta_size, meta_magic)
                            xref.meta = xref_meta
                            got_xref_meta = True
                        except BaseException as ex:
                            explict_prefix = prefix + "[add_meta]"
                            logger.warn(
                                explict_prefix + " error while try to produce and add a meta to xref\n" +
                                "[WARN]"+explict_prefix + " " + str(ex))
                    else:
                        msg = prefix + "[last=" + str(last) + "][ref_obj_finish] is not a valid ref object"
                        if not strict:
                            logger.warn(msg)
                        else:
                            logger.error(msg, throw=True)

                current_index = None
                current_magic = None
                current_type = None
                MODE = MODE_BYTE_INDEX

                index += 1
                offset += 1
                continue
            elif char == ' ':
                if MODE == MODE_XREF_START:
                    msg = prefix+"[empty_space_handle] xref start indicator contains empty space"
                    if not strict:
                        logger.warn(msg)
                    else:
                        logger.error(msg, throw=True)
                MODE += 1
                index += 1
                offset += 1
                continue
            elif MODE == MODE_XREF_START:
                part += char
                offset += 1
                continue

            if MODE == MODE_BYTE_INDEX:
                if current_index is None:
                    current_index = []
                current_index.append(byte)
            elif MODE == MODE_MAGIC:
                if current_magic is None:
                    current_magic = []
                current_magic.append(byte)
            elif MODE == MODE_TYPE:
                if current_type is None:
                    current_type = []
                current_type.append(byte)

            offset += 1
        except BaseException as ex:
            logger.error(prefix + "[error_raise_handle] " + str(ex))
            break

    if MODE == MODE_TRAILER_FOUND and current_index is not None and current_magic is not None and current_type is not None:
        xref.add(get_ref_from_lists(current_index, current_magic, current_type))

    xref.end = offset

    return xref

class BasicRef:
    index = -1
    magic = None

    def __init__(self, index, magic):
        if not type(index) == int:
            logger.error("[BasicRef] index needs to be int", throw=TYPE_SAFE)
        if not type(magic) == bytes:
            logger.error("[BasicRef] magic needs to be bytes", throw=TYPE_SAFE)
        self.index = index
        self.magic = magic

    def __repr__(self):
        return " { " + str(self.index) + " " + self.magic.decode('ascii') + " } "

class Ref:
    byte_ref = -1
    magic = None
    typ = None

    def __init__(self, byte_ref, magic, typ):
        if not type(byte_ref) == int:
            logger.error("[Ref] byte_ref needs to be int", throw=TYPE_SAFE)
        if not type(magic) == bytes:
            logger.error("[Ref] magic needs to be bytes", throw=TYPE_SAFE)
        if not type(typ) == str:
            logger.error("[Ref] type needs to be str", throw=TYPE_SAFE)
        self.byte_ref = byte_ref
        self.magic = magic
        self.typ = typ

    def __eq__(self, other):
        if not isinstance(other, Ref):
            return False

        return self.byte_ref == other.byte_ref and self.magic == other.magic and self.typ == other.typ

    def __repr__(self):
        return " { " + str(self.byte_ref) + " " + self.magic.decode('ascii') + " " + self.typ + " } "

class xRefMeta:
    magic = None
    size = -1

    def __init__(self, size, magic):
        if not type(size) == int:
            logger.error("[xRefMeta] size needs to be int", throw=TYPE_SAFE)
        if not type(magic) == bytes:
            logger.error("[xRefMeta] magic needs to be bytes", throw=TYPE_SAFE)

        self.magic = magic
        self.size = size

    def __repr__(self):
        return " { " + self.magic.decode('ascii') + " " + str(self.size) + " } "

class xRefIndicator:
    start = None
    end = None
    offset = None

    def __init__(self, start, end, offset):
        if not type(start) == int:
            logger.error("[xRefIndicator] start needs to be int", throw=TYPE_SAFE)
        if not type(end) == int:
            logger.error("[xRefIndicator] end needs to be int", throw=TYPE_SAFE)
        if not type(offset) == int:
            logger.error("[xRefIndicator] indicator needs to be int", throw=TYPE_SAFE)

        self.start = start
        self.end = end
        self.offset = offset

    def __repr__(self):
        return " { start=" + str(self.start) + " , end=" + str(self.end) + " , offset=" + str(self.offset) + " } "

class xRef:
    _refs = []
    _start = -1
    _end = -1
    _indicator = None
    _meta = None

    def __init__(self, start, indicator):
        if not type(start) == int:
            logger.error("[xRef][__init__] start needs to be int", throw=TYPE_SAFE)
        if not isinstance(indicator, xRefIndicator):
            logger.error("[xRef][__init__] indicator needs to be xRefIndicator", throw=TYPE_SAFE)

        self._start = start
        self._indicator = indicator

    def __getattr__(self, item):
        if type(item) == str:
            if item == "start":
                return self._start
            elif item == "end":
                return self._end
            elif item == "meta":
                return self._meta
        elif type(item) == int or isinstance(item, Ref) or isinstance(item, BasicRef):
            return self.__get_by_ref_or_index(item)
        logger.warn("[xRef][x{"+str(type(item))+"}][__get__] is None caused by unsupported type")
        return None

    def __setattr__(self, key, value):
        if key == "end":
            if not type(value) == int:
                logger.error("[xRef][end][__set__] end needs to be int", throw=TYPE_SAFE)
            self._end = value
        if key == "meta":
            if not isinstance(value, xRefMeta):
                logger.error("[xRef][meta][__set__] meta needs to be xRefMeta", throw=TYPE_SAFE)
            self._meta = value
        else:
            super.__setattr__(self, key, value)

    def __sizeof__(self):
        return len(self._refs)

    def add(self, other):
        if not isinstance(other, Ref):
            pass
        self._refs.append(other)

    def __get_by_ref_or_index(self, item):
        if isinstance(item, Ref):
            for ref in self._refs:
                if ref == item:
                    return item
            logger.warn("[xRef][" + str(item) + "][__get__] can not found equals ref")
            return None
        else:
            index = None
            # TODO figure out what magic is in a Basic Ref and use it
            '''
            gotMagic = False
            magic = None
            '''
            basic_prefix = ""

            if type(item) == int:
                index = item
            elif isinstance(item, BasicRef):
                index = item.index
                basic_prefix = "["+str(item)+"]"
                '''
                gotMagic = True
                magic = item.magic
                '''

            if type(index) == int and len(self._refs) > index and index > -1:
                return self._refs[index]
            logger.warn("[xRef]"+basic_prefix+"[" + str(index) + "][__get__] can not be find in xref")
        return None

    def __repr__(self):
        string = " { start=" + str(self._start) + " , end=" + str(self._end) + " , meta=" + str(self._meta) + ", indicator=" + str(self._indicator) +", refs= ["
        for ref in self._refs:
            string += str(ref) + ", "
        string += "] } "
        return string