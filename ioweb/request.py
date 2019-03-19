class Request(object):
    __slots__ = (
        'config',
        'retry_count',
        'meta',
    )

    def __init__(self, retry_count=0, meta=None, **kwargs):
        self.config = self.get_default_config()
        self.setup(**kwargs)
        self.retry_count = retry_count
        self.meta = meta or {}

    def get_default_config(self):
        return {
            'url': None,
            'max_redirects': 0,
            'certinfo': False,
            'extra_valid_status': None,
            'timeout': 10,
            'connect_timeout': 5,
            'resolve': None,
            'raw': False,
        }

    def setup(self, **kwargs):
        for key in kwargs:
            assert key in (
                'meta', 'name', 'url',
                'max_redirects', 'certinfo',
                'timeout', 'resolve',
                'raw', 'headers'
            ), 'Invalid configuration key: %s' % key
            self.config[key] = kwargs[key]

    def __getitem__(self, key):
        return self.config[key]
