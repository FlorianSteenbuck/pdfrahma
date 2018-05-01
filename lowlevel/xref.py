from lowlevel.floxio import need_input_bytes
from lowlevel.log import Logger

logger = Logger()

MODE_XREF_START = 0
MODE_BYTE_INDEX = 1
MODE_MAGIC = 2
MODE_TYPE = 3

def need_input_pdf_bytes(input, whereAmI="anonymous"):
    return need_input_bytes(input, extensions=["pdf"], whereAmI=whereAmI)

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
        except:
            pass

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
                xrefs.append(get_xref(bytes_pdf, int_saved_offset, strict=strict))
                count += 1
            except Exception as ex:
                logger.error("[get_xref][last][last_add] "+str(ex))
        offset -= 1

    return xrefs

def get_ref_from_lists(index, magic, typ):
    str_type = bytes(typ).decode("ascii")
    return Ref(
        int(bytes(index)),
        bytes(magic),
        str_type
    )

def get_xref(input, offset, strict=False):
    bytes_pdf = need_input_pdf_bytes(input, "get_xref")

    part = ''
    index = 0
    xref = xRef()

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
                except Exception as ex:
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
                    xref.add(get_ref_from_lists(current_index, current_magic, current_type))
                else:
                    msg = prefix+"[ref_obj_finish] is not a valid ref object"
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
        except Exception as ex:
            logger.error(prefix + "[error_raise_handle] " + str(ex))
            break

    if current_index is not None and current_magic is not None and current_type is not None:
        xref.add(get_ref_from_lists(current_index, current_magic, current_type))

    return xref

class BasicRef:
    index = -1
    magic = None

    def __init__(self, index, magic):
        if not type(index) == int:
            logger.error("[BasicRef] index needs to be int")
        self.index = index
        self.magic = magic

class Ref:
    byte_ref = -1
    magic = None
    typ = None

    def __init__(self, byte_ref, magic, typ):
        if not type(byte_ref) == int:
            logger.error("[Ref] byte_ref needs to be int")
        if not type(magic) == bytes:
            logger.error("[Ref] magic needs to be bytes")
        if not type(typ) == str:
            logger.error("[Ref] type needs to be str")
        self.byte_ref = byte_ref
        self.magic = magic
        self.typ = typ

    def __eq__(self, other):
        if not isinstance(other, Ref):
            return False

        return self.byte_ref == other.byte_ref and self.magic == other.magic and self.typ == other.typ

class xRef:
    _refs = []

    def __sizeof__(self):
        return len(self._refs)

    def add(self, other):
        if not isinstance(other, Ref):
            pass
        self._refs.append(other)

    def __getattr__(self, item):
        if isinstance(item, Ref):
            for ref in self._refs:
                if ref == item:
                    return item
            return None
        else:
            index = None
            # TODO figure out what magic is in a Basic Ref and use it
            '''
            gotMagic = False
            magic = None
            '''

            if type(item) == int:
                index = item
            elif isinstance(item, BasicRef):
                index = item.index
                '''
                gotMagic = True
                magic = item.magic
                '''

            if type(index) == int and len(self._refs) > index and index > -1:
                return self._refs[index]
        return None

    def __repr__(self):
        string = "["
        for ref in self._refs:
            string += " { " + str(ref.byte_ref) + " " + ref.magic.decode('ascii') + " " + ref.typ + " } , "
        string += "]"
        return string


xref = get_xrefs("/home/vornix/Downloads/11174_Kontenrahmen-DATEV-SKR-03_uncompress.pdf")[0]