class Data(object):
    __slots__ = (
        'name',
        'meta',
    )

    def __init__(self, name, meta=None):
        self.name = name
        self.meta = meta or {}

    def __getitem__(self, key):
        return self.meta[key]

    def as_data(self):
        return {
            'name': self.name,
            'meta': self.meta,
        }

    @classmethod
    def from_data(cls, data):
        req = Data()
        for key in ('name', 'storage',):
            setattr(req, key, data[key])
        return req
