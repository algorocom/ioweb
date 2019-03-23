import logging
import time
from contextlib import contextmanager

from urllib3.util.retry import Retry
from urllib3.util.timeout import Timeout
from urllib3 import exceptions
from  urllib3.contrib import pyopenssl
import urllib3

from . import error
from .urllib3_custom import CustomPoolManager

urllib3.disable_warnings(exceptions.InsecureRequestWarning)
pyopenssl.inject_into_urllib3()


class Urllib3Transport(object):
    __slots__ = (
        'urllib3_response',
        'op_started',
        'pool',
    )

    def __init__(self, pool=None):
        if pool is None:
            pool = CustomPoolManager()
        self.pool = pool
        self.urllib3_response = None

    def prepare_request(self, req, res):
        pass

    @contextmanager
    def handle_network_error(self):
        try:
            yield
        except exceptions.ReadTimeoutError as ex:
            raise error.OperationTimeoutError(str(ex), ex)
        except exceptions.ConnectTimeoutError as ex:
            raise error.ConnectError(str(ex), ex)
        except exceptions.ProtocolError as ex:
            raise error.ConnectError(str(ex), ex)
        except exceptions.SSLError as ex:
            raise error.ConnectError(str(ex), ex)


    def request(self, req, res):
        self.op_started = time.time()
        if req['resolve']:
            for host, ip in req['resolve'].items():
                self.pool.resolving_cache[host] = ip
        with self.handle_network_error():
            self.urllib3_response = self.pool.urlopen(
                req.method(),
                req['url'],
                headers=(req['headers'] or {}),
                retries=Retry(
                    total=False,
                    connect=False,
                    read=False,
                    redirect=0,
                    status=None,
                ),
                timeout=Timeout(
                    connect=req['connect_timeout'],
                    read=req['timeout'],
                ),
                preload_content=False,
            )

    def read_with_timeout(self, req, res):
        chunk_size = 1024
        while True:
            chunk = self.urllib3_response.read(chunk_size)
            if chunk:
                res._bytes_body.write(chunk)
            else:
                break
            if time.time() - self.op_started > req['timeout']:
                raise error.OperationTimeoutError(
                    'Timed out while reading response',
                )

    def prepare_response(self, req, res, err):
        try:
            if err:
                res.error = err
            else:
                try:
                    headers = {}
                    for key, val in self.urllib3_response.getheaders().items():
                        headers[key.lower()] = val
                    res._cached['parsed_headers'] = headers
                    res.status = self.urllib3_response.status

                    if hasattr(self.urllib3_response._connection.sock, 'connection'):
                        res.cert = (
                            self.urllib3_response._connection.sock.connection
                            .get_peer_cert_chain()
                        )

                    with self.handle_network_error():
                        self.read_with_timeout(req, res)
                except error.NetworkError as ex:
                    res.error = err
        finally:
            if self.urllib3_response:
                self.urllib3_response.release_conn()
