from io import BytesIO
from collections import defaultdict
#from base64 import b64encode
try:
    import ujson as json
except ImportError:
    import json

#from urllib3.contrib import pyopenssl


class Response(object):
    __slots__ = (
        '_bytes_body',
        '_cached',
        'cert',
        'status',
        'error',
        'headers',
    )

    def __init__(self):
        self._bytes_body = BytesIO()
        self.headers = None
        self.cert = None
        self.status = None
        self.error = None

    def write_bytes_body(self, data):
        return self._bytes_body.write(data)

    @property
    def data(self):
        return self.bytes_body

    @property
    def text(self):
        return self.data.decode('utf-8')

    @property
    def bytes_body(self):
        return self._bytes_body.getvalue()

    @property
    def json(self):
        return json.loads(self.text)

    def get_content_type(self):
        if self.headers:
            return (
                self.headers.get('content-type', '').split(';')[0].strip()
            )
        else:
            return None
