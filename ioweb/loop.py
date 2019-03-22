import pycurl
from queue import Empty
import time
import sys
import logging
from collections import deque
from threading import Thread

from .pycurl_transport import PycurlTransport
from .util import debug
from .response import Response
from .error import build_network_error
from .pycurl_hack import PycurlSigintHandler

network_logger = logging.getLogger('ioweb.network')


class MultiCurlLoop(object):
    def __init__(
            self, taskq, resultq, threads=3, resultq_size_limit=None,
            shutdown_event=None,
            pause=None,
            setup_handler_hook=None
        ):
        if resultq_size_limit is None:
            resultq_size_limit = threads * 2
        self.setup_handler_hook = setup_handler_hook
        self.taskq = taskq
        self.resultq = resultq
        self.resultq_size_limit = resultq_size_limit
        self.idle_handlers = set()
        self.active_handlers = set()
        self.registry = {}
        self.shutdown_event = shutdown_event
        self.pause = pause
        self.threads = threads
        for _ in range(threads):
            ref = object()
            self.idle_handlers.add(ref)
            handler = pycurl.Curl()
            handler._reference = ref
            self.registry[ref] = {
                'handler': handler,
                'transport': PycurlTransport(),
                'request': None,
                'response': None,
                'start': None,
            }
        self.multi = pycurl.CurlMulti()
        self._sigint_handler = PycurlSigintHandler()
        self.list_prepare_handler = deque()
        self.list_completed_handler = deque()
        self.list_add_handler = deque()
        self.list_remove_handler = deque()

    def thread_things(self):
        task = None
        while not self.shutdown_event.is_set():
            action = False
            if len(self.list_prepare_handler):
                ref, req = self.list_prepare_handler.popleft()
                self.prepare_handler(ref, req)
                action = True
            if len(self.list_completed_handler):
                hdl, errno, errmsg = self.list_completed_handler.popleft()
                self.handle_completed_handler(hdl, errno, errmsg)
                action = True
            if (
                    task is None
                    and
                    self.resultq.qsize() < self.resultq_size_limit
                ):
                try:
                    task = self.taskq.get(False)
                except Empty:
                    pass

            if task and len(self.idle_handlers):
                ref = self.idle_handlers.pop()
                self.list_prepare_handler.append((ref, task))
                task = None
                action = True
            if not action:
                time.sleep(0.001)

    def run(self):
        task = None

        th = Thread(target=self.thread_things)
        th.start()

        while not self.shutdown_event.is_set():
            if self.pause.pause_event.is_set():
                if (
                        task is None
                        and not len(self.active_handlers)
                        and len(self.idle_handlers) == self.threads
                    ):
                    self.pause.process_pause()

            for _ in range(5):
                while len(self.list_add_handler):
                    ref = self.list_add_handler.popleft()
                    handler = self.registry[ref]['handler']
                    self.multi.add_handle(handler)

                while len(self.list_remove_handler):
                    ref = self.list_remove_handler.popleft()
                    self.registry[ref]['handler'].reset()
                    self.idle_handlers.add(ref)

                ret = self.multi.select(0.01)
                if ret != -1:
                    break

            if ret != -1:
                with self._sigint_handler.handle_sigint():
                    while True:
                        ret, num_handles = self.multi.perform()
                        if ret != pycurl.E_CALL_MULTI_PERFORM:
                            break
                num_active, ok_handlers, fail_handlers = self.multi.info_read()
                for item in ok_handlers:
                    self.multi.remove_handle(item)
                    self.list_completed_handler.append((item, None, None))
                for item in fail_handlers:
                    self.multi.remove_handle(item[0])
                    self.list_completed_handler.append((item[0], item[1], item[2]))

    def prepare_handler(self, ref, req):
        handler = self.registry[ref]['handler']
        transport = self.registry[ref]['transport']
        transport.set_handler(handler)
        res = Response()
        transport.prepare_request(req, res)
        self.active_handlers.add(ref)
        if req.retry_count > 0:
            retry_str = ' [retry #%d]' % req.retry_count
        else:
            retry_str = ''
        network_logger.debug(
            'GET %s%s', req['url'], retry_str
        )
        self.registry[ref]['request'] = req
        self.registry[ref]['response'] = res
        self.registry[ref]['start'] = time.time()

        if self.setup_handler_hook:
            self.setup_handler_hook(transport, req)
        self.list_add_handler.append(ref)

    def free_handler(self, ref):
        self.active_handlers.remove(ref)
        self.list_remove_handler.append(ref)
        self.registry[ref]['request'] = None
        self.registry[ref]['response'] = None
        self.registry[ref]['start'] = None

    def handle_completed_handler(self, hdl, errno, errmsg):
        ref = hdl._reference
        transport = self.registry[ref]['transport']
        req = self.registry[ref]['request']
        res = self.registry[ref]['response']
        if errno:
            err = build_network_error(errno, errmsg)
        else:
            err = None
        transport.prepare_response(req, res, err)
        self.free_handler(ref)
        self.resultq.put({
            'request': req,
            'response': res,
        })
