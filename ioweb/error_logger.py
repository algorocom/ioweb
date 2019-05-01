from datetime import datetime
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


class MongodbHandler(object):
    def __init__(self, **kwargs):
        from pymongo import MongoClient

        self.db_name = kwargs.pop('database', 'ioweb')
        self.col_name = kwargs.pop('collection', 'crawler_error')
        self.connection_args = kwargs
        self.db = MongoClient(**kwargs)[self.db_name]

    def handle_error(self, exc_info, ctx=None):
        ctx = ctx or {}
        ctx['traceback'] = ''.join(format_exception(*exc_info))
        ctx['error_type'] = exc_info[0].__name__
        ctx['error_msg'] = str(exc_info[1])
        self.db[self.col_name].insert_one({
            'date': datetime.utcnow(),
            'data': ctx,
        })


class ErrorLogger(object):
    aliases = {
        'file': FileHandler,
    }

    def __init__(self):
        self.handlers = []

    def add_handler(self, hdl, remove_handlers=False):
        if remove_handlers:
            self.handlers = []
        if isinstance(hdl, str):
            hdl = self.aliases[hdl]() 
        self.handlers.append(hdl)

    def log_error(self, exc_info, ctx=None):
        for hdl in self.handlers:
            hdl.handle_error(exc_info, ctx)
