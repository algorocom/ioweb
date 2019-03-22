import sys
from contextlib import contextmanager
from io import TextIOBase, StringIO


class PycurlSigintHandler(TextIOBase):
    # TextIOBase to avoid errors in py36: https://bugs.python.org/issue29130
    def __init__(self, *args, **kwargs):
        super(PycurlSigintHandler, self).__init__(*args, **kwargs)
        self.orig_stderr = None
        self.buf = None

    @contextmanager
    def record(self):
        # NB: it is not thread-safe
        self.buf = StringIO()
        self.orig_stderr = sys.stderr
        try:
            sys.stderr = self
            yield
        finally:
            sys.stderr = self.orig_stderr

    def write(self, data):
        self.orig_stderr.write(data)
        self.buf.write(data)

    def get_output(self):
        return self.buf.getvalue()

    @contextmanager
    def handle_sigint(self):
        with self.record():
            try:
                yield
            except Exception: # pylint: disable=broad-except
                if 'KeyboardInterrupt' in self.get_output():
                    raise KeyboardInterrupt
                else:
                    raise
            else:
                if 'KeyboardInterrupt' in self.get_output():
                    raise KeyboardInterrupt

