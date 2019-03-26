from .stat import Stat


class TaskGenerator(object):
    def __init__(self):
        self.stat = Stat()
        self.init_hook()

    def init_hook(self):
        pass

    def task_generator(self):
        raise NotImplementedError
