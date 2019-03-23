from gevent import monkey
monkey.patch_all()#thread=False)

from .session import Session
from .request import Request
from .response import Response
from .crawler import Crawler
from .urllib3_transport import Urllib3Transport
