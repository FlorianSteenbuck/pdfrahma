from xlog import Logger
from xref import xRefIndicator
from xcore import need_input_pdf_bytes
from xio import byte_to_char

logger = Logger("xghost")
TYPE_SAFE = True

def parse_trailer_by_indicators(input, indicators):
    if not type(indicators) == tuple or not isinstance(indicators[0], xRefIndicator):
        logger.error("[parse_dict_context] indicators needs to be a tuple of xRefIndicator", throw=TYPE_SAFE)
    pdf_bytes = need_input_pdf_bytes(input, "parse_trailer_by_indicators")

def parse_dict_context(input, regions=[]):
    pdf_bytes = need_input_pdf_bytes(input, "parse_dict_context")
    if len(regions) <= 0:
        regions = [(0, len(pdf_bytes))]
    for region in regions:
        if len(region) > 0:
            continue
        for i in range(region[0], region[1]):
            char = byte_to_char(pdf_bytes[i], "ascii")