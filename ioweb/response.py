from io import BytesIO
from collections import defaultdict
try:
    import ujson as json
except ImportError:
    import json

import pycurl


class Response(object):
    __slots__ = (
        '_bytes_headers',
        '_bytes_body',
        '_cached',
        'certinfo',
        'status',
        'error',
    )

    def __init__(self):
        self._bytes_headers = BytesIO()
        self._bytes_body = BytesIO()
        self._cached = {
            'parsed_headers': None,
            'text_headers': None,
        }
        self.certinfo = None
        self.status = None
        self.error = None

    def write_bytes_body(self, data):
        return self._bytes_body.write(data)

    def write_bytes_headers(self, data):
        return self._bytes_headers.write(data)

    def parse_headers(self, text_headers):
        reg = defaultdict(list)
        for item in text_headers.split('\r\n'):
            delim_idx = item.find(':')
            if delim_idx > -1:
                key, val = (
                    item[0 : delim_idx].strip().lower(),
                    item[delim_idx + 1 : ].strip(),
                )
                reg[key].append(val)
        return reg

    @property
    def data(self):
        return self.bytes_body

    @property
    def text(self):
        return self.data.decode('utf-8')

    @property
    def bytes_headers(self):
        return self._bytes_headers.getvalue()

    @property
    def text_headers(self):
        if self._cached['text_headers'] is None:
            self._cached['text_headers'] = (
                self.bytes_headers.decode('iso 8859-1', 'ignore')
            )
        return self._cached['text_headers']

    @property
    def last_text_headers(self):
        # find last response headers, they are in \r\n\r\n(...)\r\n\r\n$
        idx = self.text_headers.rfind('\r\n\r\n', 0, -4)
        if idx == -1:
            idx = -4
        return self.text_headers[idx + 4 : -4]

    @property
    def bytes_body(self):
        return self._bytes_body.getvalue()

    @property
    def headers(self):
        if self._cached['parsed_headers'] is None:
            self._cached['parsed_headers'] = self.parse_headers(
                self.last_text_headers
            )
        return self._cached['parsed_headers']

    @property
    def json(self):
        return json.loads(self.text)
