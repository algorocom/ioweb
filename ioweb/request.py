class BaseRequest(object):
    __slots__ = (
        'config',
        'retry_count',
        'priority',
        'meta',
        'retry_errors',
        'error_context',
    )
    valid_config_keys = () 

    def __init__(
            self, retry_count=0, priority=100, meta=None,
            retry_errors=None, error_context=None,
            **kwargs
        ):
        self.retry_count = retry_count
        self.priority = priority
        self.meta = meta or {}
        self.config = self.get_default_config()
        assert \
            retry_errors is None or isinstance(retry_errors, tuple), \
            'retry_errors must be None or tuple'
        self.retry_errors = retry_errors
        self.error_context = error_context
        self.setup(**kwargs)


    def get_default_config(self):
        return {}

    def setup(self, **kwargs):
        for key in kwargs:
            assert key in self.valid_config_keys, 'Invalid configuration key: %s' % key
            self.config[key] = kwargs[key]

    def __getitem__(self, key):
        return self.config[key]

    def as_data(self):
        return {
            'config': self.config,
            'retry_count': self.retry_count,
            'priority': self.priority,
            'meta': self.meta,
        }

    @classmethod
    def from_data(cls, data):
        req = Request()
        for key in ('config', 'retry_count', 'priority', 'meta'):
            setattr(req, key, data[key])
        return req

    def __lt__(self, other):
        return self.priority < other.priority

    def __eq__(self, other):
        #if not self.priority or not other.priority:
        #    return True
        #else:
        return self.priority == other.priority


class Request(BaseRequest):
    valid_config_keys = (
        'name', 'url',
        'max_redirects',
        'timeout', 'connect_timeout',
        'resolve', 'raw', 'headers',
        'content_encoding', 'decode_content',
        'content_read_limit', 'priority',
        'extra_valid_status',
        'proxy', 'proxy_auth', 'proxy_type',
        'data', 'multipart', 'verify',
    )

    def get_default_config(self):
        return {
            'method': None,
            'name': None,
            'url': None,
            'max_redirects': 0,
            'timeout': 10,
            'connect_timeout': 5,
            'resolve': None,
            'raw': False,
            'headers': None,
            'content_encoding': 'gzip,chunked', 
            'decode_content': True,
            'content_read_limit': None,
            'priority': 100,
            'extra_valid_status': None,
            'proxy': None,
            'proxy_auth': None,
            'proxy_type': 'http',
            'data': None,
            'multipart': False,
            'verify': True,
        }

    def method(self):
        if self.config['method']:
            return self.config['method']
        elif self.config['data']:
            return 'POST'
        else:
            return 'GET'


class CallbackRequest(BaseRequest):
    """
    CallbackRequest is not processed with network transport.
    It has `network_callback` which is
    executed instead of `transport.request`
    """
    valid_config_keys = (
        'name',
        'timeout',
        'raw',
        'network_callback',
    )

    def get_default_config(self):
        return {
            'name': None,
            'timeout': 10,
            'raw': False,
            'network_callback': None,
        }
