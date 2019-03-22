import pycurl
import logging
import time
from contextlib import contextmanager

from urllib3.util.retry import Retry
from urllib3.util.timeout import Timeout
from urllib3 import exceptions
import urllib3

from . import error
from .urllib3_custom import CustomPoolManager

urllib3.disable_warnings()


class Urllib3Transport(object):
    __slots__ = (
        '_response',
        'op_started',
        'pool',
    )

    def __init__(self, pool=None):
        if pool is None:
            pool = CustomPoolManager()
        self.pool = pool
        self._response = None

    def prepare_request(self, req, res):
        """
        self.handler # ensure pycurl object is created

        # libcurl/pycurl is not thread-safe by default.  When multiple threads
        # are used, signals should be disabled.  This has the side effect
        # of disabling DNS timeouts in some environments (when libcurl is
        # not linked against ares)
        self._handler.setopt(pycurl.NOSIGNAL, 1)

        self._handler.setopt(pycurl.URL, req.config['url'])
        self._handler.setopt(
            pycurl.WRITEFUNCTION, res.write_bytes_body,
        )
        self._handler.setopt(
            pycurl.HEADERFUNCTION, res.write_bytes_headers,
        )
        self._handler.setopt(pycurl.FOLLOWLOCATION, 0)
        self._handler.setopt(
            pycurl.OPT_CERTINFO,
            1 if req.config['certinfo'] else 0
        )
        self._handler.setopt(pycurl.SSL_VERIFYPEER, 0)
        self._handler.setopt(pycurl.SSL_VERIFYHOST, 0)
        self._handler.setopt(pycurl.TIMEOUT, req['timeout'])
        self._handler.setopt(pycurl.CONNECTTIMEOUT, req['connect_timeout'])
        if req['resolve']:
            self._handler.setopt(pycurl.RESOLVE, req['resolve'])
        if req['headers']:
            self._handler.setopt(
                pycurl.HTTPHEADER,
                ['%s: %s' %x for x in req['headers'].items()]
            )
        """
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
        # TODO: resolv
        self.op_started = time.time()
        if req['resolve']:
            for host, ip in req['resolve'].items():
                self.pool.resolving_cache[host] = ip
        with self.handle_network_error():
            self._response = self.pool.urlopen(
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

    def prepare_response(self, req, res, err):
        try:
            if err:
                res.error = err
            else:
                try:
                    with self.handle_network_error():
                        # TODO certinfo, status
                        headers = {}
                        for key, val in self._response.getheaders().items():
                            headers[key.lower()] = val
                        res._cached['parsed_headers'] = headers
                        res.status = self._response.status

                        def read_with_timeout():
                            chunk_size = 10000
                            while True:
                                chunk = self._response.read(chunk_size)
                                if chunk:
                                    res._bytes_body.write(chunk)
                                else:
                                    break
                                if time.time() - self.op_started > req['timeout']:
                                    raise error.OperationTimeoutError(
                                        'Timed out while reading response',
                                    )

                        read_with_timeout()
                except error.NetworkError as ex:
                    res.error = err
        finally:
            if self._response:
                self._response.release_conn()
