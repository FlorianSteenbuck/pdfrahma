from xlog import Logger

logger = Logger("xio")

def byte_to_char(byte, encoding):
    return bytes([byte]).decode(encoding)

def file_get_contents(path, binary=False):
    mode = 'r'
    if binary:
        mode += 'b'

    with open(path, mode) as pdf_file:
        return pdf_file.read()

def need_input_bytes(input, extensions, whereAmI = "anonymous"):
    bytes = None
    if type(input) == str:
        str_pdf = input
        # TODO find a way to detect a raw pdf string
        extsplit = input.split(".")
        if extsplit[len(extsplit) - 1] in extensions:
            str_pdf = file_get_contents(input, binary=True)
        bytes = bytearray(str_pdf)
    else:
        if not (type(input) == bytes or type(input) == bytearray):
            logger.warn("["+whereAmI+"] input is not byte array and not string try to convert to byte array")

        # stick to one builtin that what I want is somehow a array so I take here bytearray
        # TODO check if bytearray is bytes and remove casting
        bytes = bytearray(input)
    return bytes