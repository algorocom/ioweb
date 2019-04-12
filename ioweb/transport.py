import logging
import time
from contextlib import contextmanager
import traceback
import sys

from urllib3.util.retry import Retry
from urllib3.util.timeout import Timeout
from urllib3 import exceptions
from  urllib3.contrib import pyopenssl
import urllib3
import OpenSSL.SSL

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
        except OpenSSL.SSL.Error as ex:
            raise error.ConnectError(str(ex), ex)
        except exceptions.LocationParseError as ex:
            raise error.MalformedResponseError(str(ex), ex)
        except exceptions.DecodeError as ex:
            raise error.MalformedResponseError(str(ex), ex)
        except AttributeError:
            # See https://github.com/urllib3/urllib3/issues/1556
            etype, evalue, tb = sys.exc_info()
            frames = traceback.extract_tb(tb)
            found = False
            for frame in frames:
                if (
                        "if host.startswith('[')" in frame.line
                        and 'connectionpool.py' in frame.filename
                    ):
                    found = True
                    break
            if found:
                raise error.MalformedResponseError('Invalid redirect header')
            else:
                raise
        except ValueError as ex:
            if 'Invalid IPv6 URL' in str(ex):
                raise error.MalformedResponseError('Invalid redirect header')
            else:
                raise


    def request(self, req, res):
        self.op_started = time.time()
        if req['resolve']:
            for host, ip in req['resolve'].items():
                self.pool.resolving_cache[host] = ip
        headers = req['headers'] or {}
        if req['content_encoding']:
            if not any(x.lower() == 'accept-encoding' for x in headers):
                headers['accept-encoding'] = req['content_encoding']
        with self.handle_network_error():
            self.urllib3_response = self.pool.urlopen(
                req.method(),
                req['url'],
                headers=headers,
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
                decode_content=req['decode_content'],
            )

    def read_with_timeout(self, req, res):
        read_limit = req['content_read_limit']
        chunk_size = 1024
        bytes_read = 0
        while True:
            chunk = self.urllib3_response.read(chunk_size)
            if chunk:
                if read_limit:
                    chunk_limit = min(len(chunk), read_limit - bytes_read)
                else:
                    chunk_limit = len(chunk)
                res._bytes_body.write(chunk[:chunk_limit])
                bytes_read += chunk_limit
                if read_limit and bytes_read >= read_limit:
                    break
            else:
                break
            if time.time() - self.op_started > req['timeout']:
                raise error.OperationTimeoutError(
                    'Timed out while reading response',
                )

    def prepare_response(self, req, res, err, raise_network_error=True):
        try:
            if err:
                res.error = err
            else:
                try:
                    res.headers = self.urllib3_response.headers
                    res.status = self.urllib3_response.status

                    if hasattr(self.urllib3_response._connection.sock, 'connection'):
                        res.cert = (
                            self.urllib3_response._connection.sock.connection
                            .get_peer_cert_chain()
                        )

                    with self.handle_network_error():
                        self.read_with_timeout(req, res)
                except error.NetworkError as ex:
                    if raise_network_error:
                        raise
                    else:
                        res.error = err
        finally:
            if self.urllib3_response:
                self.urllib3_response.release_conn()
