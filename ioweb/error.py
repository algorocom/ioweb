"""
TODO: remove curl references
"""
class IowebError(Exception):
    pass


class NetworkError(IowebError):
    """
    NetworkError instance stores original transport-specific error
    in `transport_error` attribute.
    """
    def __init__(self, *args):
        self.errmsg = None
        self.transport_error = None
        if len(args) > 0:
            self.errmsg = args[0]
        if len(args) > 1:
            self.transport_error = args[1]

    def get_tag(self):
        return self.transport_error.__class__.__name__.lower()


class DataWriteError(NetworkError):
    """
    An error occurred when writing received data to a local file,
    or an error was returned to libcurl from a write callback.
    """


class OperationTimeoutError(NetworkError):
    """
    Operation timeout. The specified time-out period was reached
    according to the conditions.
    """


class ConnectError(NetworkError):
    """
    Failed to connect() to host or proxy.
    """


class AuthError(NetworkError):
    """
    The remote server denied client to login (Added in 7.13.1)
    """


class TooManyRedirectsError(NetworkError):
    """
    Too many redirects. When following redirects, libcurl hit the
    maximum amount. Set your limit with CURLOPT_MAXREDIRS.
    """


class ResolveHostError(NetworkError):
    """
    Couldn't resolve host. The given remote host was not resolved.
    """


class InvalidUrlError(NetworkError):
    """
    The URL was not properly formatted.
    """


class MalformedResponseError(NetworkError):
    """
    Raised when parser fails to parse response HTTP headers
    """


ERRNO_CLASS_MAPPING = {
    3: InvalidUrlError,
    6: ResolveHostError,
    7: ConnectError,
    23: DataWriteError,
    28: OperationTimeoutError,
    47: TooManyRedirectsError,
    67: AuthError,
}
