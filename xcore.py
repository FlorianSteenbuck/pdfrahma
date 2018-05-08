from xio import need_input_bytes

def need_input_pdf_bytes(input, whereAmI="anonymous"):
    return need_input_bytes(input, extensions=["pdf"], whereAmI=whereAmI)