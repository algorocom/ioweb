from traceback import format_exception


class FileHandler(object):
    def __init__(self, path='var/log/fail.log', mode='a'):
        self.logfile = open(path, mode)

    def handle_error(self, exc_info, ctx=None):
        if ctx:
            ctx_data = ''.join(
                '%s: %s\n' % (x, y) for (x, y)
                in sorted(ctx.items(), key=lambda x: x[0])
            )
        else:
            ctx_data = ''
        self.logfile.write(
            '%s'
            '%s\n'
            '---\n' % (
                ctx_data,
                ''.join(format_exception(*exc_info)),
            )
        )
        self.logfile.flush()


class ErrorLogger(object):
    aliases = {
        'file': FileHandler,
    }

    def __init__(self):
        self.handlers = []

    def add_handler(self, hdl):
        if isinstance(hdl, str):
            hdl = self.aliases[hdl]() 
        self.handlers.append(hdl)

    def log_error(self, exc_info, ctx=None):
        for hdl in self.handlers:
            hdl.handle_error(exc_info, ctx)
