from io import BytesIO
from collections import defaultdict
#from base64 import b64encode
try:
    import ujson as json
except ImportError:
    import json

import defusedxml.lxml
from lxml.etree import HTMLParser
from selection import XpathSelector
from cssselect import HTMLTranslator

#from urllib3.contrib import pyopenssl


class CssSelector(XpathSelector):
    __slots__ = ()

    def process_query(self, query):
        xpath_query = HTMLTranslator().css_to_xpath(query)
        return super(CssSelector, self).process_query(xpath_query)


class Response(object):
    __slots__ = (
        '_bytes_body',
        '_cached',
        'cert',
        'status',
        'error',
        'headers',
        'meta',
        '_cached_dom',
    )

    def __init__(self):
        self._bytes_body = BytesIO()
        self.headers = None
        self.cert = None
        self.status = None
        self.error = None
        self.meta = {}
        self._cached_dom = None

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

    def dom(self):
        if self._cached_dom is None:
            res = defusedxml.lxml.parse(BytesIO(self.data), HTMLParser())
            self._cached_dom = res.getroot()
        return self._cached_dom

    def xpath(self, query):
        return XpathSelector(self.dom()).select(query)

    def css(self, query):
        return CssSelector(self.dom()).select(query)
