import logging
from collections import defaultdict
from threading import Event
import time

debug_logger = logging.getLogger('debug')
DEBUG_TIMES = defaultdict(int)


class Pause(object):
    def __init__(self):
        self.pause_event = Event()
        self.is_paused = Event()
        self.resume_event = Event()

    def process_pause(self):
        self.pause_event.clear()
        self.resume_event.clear() # as a precaution
        self.is_paused.set()
        self.resume_event.wait()
        self.is_paused.clear()
        self.resume_event.clear()


def debug(msg, *args):
    if time.time() - DEBUG_TIMES[msg] >= 0.5:
        debug_logger.debug(msg, *args)
        DEBUG_TIMES[msg] = time.time()
