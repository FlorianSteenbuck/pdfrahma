def print_maybe(values, maybe):
    if maybe:
        print(values)

class Logger:
    DEBUG = True
    WARN = True
    ERROR = True

    def debug(self, value):
        print_maybe('[DEBUG]' + value, self.DEBUG)

    def warn(self, value):
        print_maybe('[WARN]' + value, self.WARN)

    def error(self, value, throw=False):
        if self.ERROR:
            if not throw:
                print('[ERROR]' + value)
            else:
                raise value