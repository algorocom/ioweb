from gevent import monkey
monkey.patch_all()#thread=False)

__version__ = '0.0.5'

try:
    import grpc
except ImportError:
    pass
else:
    if grpc.__version__ != '1.18.0':
        raise Exception('grpcio version must be 1.18.0')
    from grpc.experimental import gevent
    gevent.init_gevent()

from .session import Session
from .request import Request
from .data import Data
from .response import Response
from .crawler import Crawler
from .transport import Urllib3Transport
from .task_generator import TaskGenerator
