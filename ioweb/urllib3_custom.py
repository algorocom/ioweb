"""
Credit: https://github.com/Roadmaster/forcediphttpsadapter/blob/master/forcediphttpsadapter/adapters.py
"""
import logging

from urllib3.util import connection
from urllib3.connectionpool import HTTPSConnectionPool, HTTPConnectionPool
from urllib3.connection import HTTPSConnection, DummyConnection, HTTPConnection
from urllib3 import PoolManager
from urllib3.poolmanager import SSL_KEYWORDS
from socket import error as SocketError, timeout as SocketTimeout
from urllib3.exceptions import (
    ConnectTimeoutError,
    NewConnectionError,
)
from cachetools import TTLCache

log = logging.getLogger(__name__)


class CustomHttpsConnection(HTTPSConnection, object):
    def __init__(self, *args, **kwargs):
        # custom: begins
        self.custom_ip = kwargs.pop('custom_ip', None)
        # custom: ends
        super(CustomHttpsConnection, self).__init__(*args, **kwargs)

    def _new_conn(self):
        extra_kw = {}
        if self.source_address:
            extra_kw['source_address'] = self.source_address

        if self.socket_options:
            extra_kw['socket_options'] = self.socket_options

        custom_host = self.custom_ip if self.custom_ip else self._dns_host
        #if self.custom_ip:
        #    logging.debug('Using custom ip %s for host %s' % (self.custom_ip, self._dns_host))

        try:
            conn = connection.create_connection(
                (custom_host, self.port), self.timeout, **extra_kw)

        except SocketTimeout as e:
            raise ConnectTimeoutError(
                self, "Connection to %s timed out. (connect timeout=%s)" %
                (self.host, self.timeout))

        except SocketError as e:
            raise NewConnectionError(
                self, "Failed to establish a new connection: %s" % e)

        return conn


class CustomHttpConnection(HTTPConnection, object):
    def __init__(self, *args, **kwargs):
        # custom: begins
        self.custom_ip = kwargs.pop('custom_ip', None)
        # custom: ends
        super(CustomHttpConnection, self).__init__(*args, **kwargs)

    def _new_conn(self):
        extra_kw = {}
        if self.source_address:
            extra_kw['source_address'] = self.source_address

        if self.socket_options:
            extra_kw['socket_options'] = self.socket_options

        custom_host = self.custom_ip if self.custom_ip else self._dns_host
        #if self.custom_ip:
        #    logging.debug('Using custom ip %s for host %s' % (self.custom_ip, self._dns_host))

        try:
            conn = connection.create_connection(
                (custom_host, self.port), self.timeout, **extra_kw)

        except SocketTimeout as e:
            raise ConnectTimeoutError(
                self, "Connection to %s timed out. (connect timeout=%s)" %
                (self.host, self.timeout))

        except SocketError as e:
            raise NewConnectionError(
                self, "Failed to establish a new connection: %s" % e)

        return conn


class CustomHttpConnectionPool(HTTPConnectionPool):
    def __init__(self, *args, **kwargs):
        # custom: begins
        self.custom_ip = kwargs.pop('custom_ip', None)
        # custom: ends
        super(CustomHttpConnectionPool, self).__init__(*args, **kwargs)

    def _new_conn(self):
        self.num_connections += 1
        log.debug("Starting new HTTP connection (%d): %s:%s",
                  self.num_connections, self.host, self.port or "80")


        # custom: begins
        self.conn_kw = getattr(self, 'conn_kw', {})
        self.conn_kw['custom_ip'] = self.custom_ip
        # custom: ends

        conn = CustomHttpConnection(
            host=self.host, port=self.port,
            timeout=self.timeout.connect_timeout,
            strict=self.strict, **self.conn_kw
        )
        return conn

class CustomHttpsConnectionPool(HTTPSConnectionPool):
    def __init__(self, *args, **kwargs):
        # custom: begins
        self.custom_ip = kwargs.pop('custom_ip', None)
        # custom: ends
        super(CustomHttpsConnectionPool, self).__init__(*args, **kwargs)

    def _new_conn(self):
        self.num_connections += 1
        log.debug("Starting new HTTPS connection (%d): %s:%s",
                  self.num_connections, self.host, self.port or "443")

        if not self.ConnectionCls or self.ConnectionCls is DummyConnection:
            raise SSLError("Can't connect to HTTPS URL because the SSL "
                           "module is not available.")
        actual_host = self.host
        actual_port = self.port
        if self.proxy is not None:
            actual_host = self.proxy.host
            actual_port = self.proxy.port

        # custom: begins
        self.conn_kw = getattr(self, 'conn_kw', {})
        self.conn_kw['custom_ip'] = self.custom_ip
        # custom: ends

        conn = CustomHttpsConnection(
            host=actual_host,
            port=actual_port,
            timeout=self.timeout.connect_timeout,
            strict=self.strict,
            # custom: begins
            #cert_file=self.cert_file,
            #key_file=self.key_file,
            #key_password=self.key_password,
            # custom: ends
            **self.conn_kw
        )
        return self._prepare_conn(conn)

    # custom: begins
    def __str__(self):
        return ('%s(host=%r, port=%r, custom_ip=%s)' % (
            type(self).__name__,
            self.host,
            self.port,
            self.custom_ip,
        ))
    # custom: ends


class CustomPoolManager(PoolManager):

    def __init__(self, *args, **kwargs):
        super(CustomPoolManager, self).__init__(*args, **kwargs)
        # custom: begins
        self.resolving_cache = TTLCache(maxsize=10000, ttl=(60 * 60))
        self.pool_classes_by_scheme = {
            'http': CustomHttpConnectionPool,
            'https': CustomHttpsConnectionPool,
        }
        # custom: ends

    # custom: begins
    def get_custom_ip(self, host):
        return self.resolving_cache.get(host, None)
    # custom: ends

    def _new_pool(self, scheme, host, port, request_context=None):
        pool_cls = self.pool_classes_by_scheme[scheme]
        if request_context is None:
            request_context = self.connection_pool_kw.copy()

        # Although the context has everything necessary to create the pool,
        # this function has historically only used the scheme, host, and port
        # in the positional args. When an API change is acceptable these can
        # be removed.
        for key in ('scheme', 'host', 'port'):
            request_context.pop(key, None)

        if scheme == 'http':
            for kw in SSL_KEYWORDS:
                request_context.pop(kw, None)

        # custom: begins
        custom_ip = self.get_custom_ip(host)
        if custom_ip:
            request_context['custom_ip'] = self.resolving_cache[host]
        # custom: ends

        return pool_cls(host, port, **request_context)
