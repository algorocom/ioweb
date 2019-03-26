from pprint import pprint

from .response import Response
from .request import Request
from .transport import Urllib3Transport
from .error import NetworkError


class Session(object):
    def __init__(self):
        self.req = Request()
        self.transport = Urllib3Transport()

    def setup(self, **kwargs):
        self.req.setup(**kwargs)

    def request(self, url=None, **kwargs):
        self.setup(url=url, **kwargs)
        res = Response()
        self.transport.prepare_request(self.req, res)
        self.transport.request(self.req, res)
        self.transport.prepare_response(self.req, res, None)
        return res
