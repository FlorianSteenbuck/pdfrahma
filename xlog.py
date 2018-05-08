def print_maybe(values, maybe):
    if maybe:
        print(values)

class Logger:
    DEBUG = True
    WARN = True
    ERROR = True
    _module = None

    def __init__(self, module):
        self._module = module

    def _module_prefix(self):
        return "["+str(self._module).upper()+"]"

    def debug(self, value):
        print_maybe(self._module_prefix()+'[DEBUG]' + value, self.DEBUG)

    def warn(self, value):
        print_maybe(self._module_prefix()+'[WARN]' + value, self.WARN)

    def error(self, value, throw=False):
        prefixed = self._module_prefix()+'[ERROR]'+ value
        if self.ERROR:
            if not throw:
                print(prefixed)
            else:
                raise prefixed