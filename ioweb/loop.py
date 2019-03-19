import pycurl
from queue import Empty
import logging

from .transport import CurlTransport
from .util import debug
from .response import Response
from .error import build_network_error

network_logger = logging.getLogger('ioweb.network')


class MultiCurlLoop(object):
    def __init__(
            self, taskq, resultq, threads=3, resultq_size_limit=None,
            shutdown_event=None,
            pause=None,
        ):
        if resultq_size_limit is None:
            resultq_size_limit = threads * 2
        self.taskq = taskq
        self.resultq = resultq
        self.resultq_size_limit = resultq_size_limit
        self.idle_handlers = set()
        self.active_handlers = set()
        self.registry = {}
        self.shutdown_event = shutdown_event
        self.pause = pause
        for _ in range(threads):
            hdl = pycurl.Curl()
            self.idle_handlers.add(hdl)
            self.registry[hdl] = {
                'transport': CurlTransport(),
                'request': None,
                'response': None,
            }
        self.multi = pycurl.CurlMulti()

    def run(self):
        task = None
        while not self.shutdown_event.is_set():
            if self.pause.pause_event.is_set():
                if task is None and not len(self.active_handlers):
                    self.pause.process_pause()
            #debug('-- loop: task = %s', task)
            #debug('-- loop: resultq.qsize = %d', self.resultq.qsize())
            #debug('-- loop: resultq_size_limit = %d', self.resultq_size_limit)
            if (
                    task is None
                    and
                    self.resultq.qsize() < self.resultq_size_limit
                ):
                try:
                    task = self.taskq.get(False)
                except Empty:
                    pass

            task_exists = (task is not None)
            if task and len(self.idle_handlers):
                self.start_request(task)
                task = None

            while True:
                ret, num_handles = self.multi.perform()
                if ret != pycurl.E_CALL_MULTI_PERFORM:
                    break

            # If task is waiting to be processed
            # or task has been put in processing
            # then do not wait on select
            if task_exists and len(self.idle_handlers):
                ret = 1
            else:
                ret = self.multi.select(0.1)
            if ret != -1:
                ret, num_handlers = self.multi.perform()
                num_active, ok_handlers, fail_handlers = self.multi.info_read()
                for item in ok_handlers:
                    self.handle_completed_handler(item, None, None)
                for item in fail_handlers:
                    self.handle_completed_handler(item[0], item[1], item[2])

    def start_request(self, req):
        hdl = self.idle_handlers.pop()
        transport = self.registry[hdl]['transport']
        transport.set_handler(hdl)
        res = Response()
        transport.prepare_request(req, res)
        self.active_handlers.add(hdl)
        if req.retry_count > 0:
            retry_str = ' [retry #%d]' % req.retry_count
        else:
            retry_str = ''
        network_logger.debug(
            'GET %s%s', req['url'], retry_str
        )
        self.multi.add_handle(hdl)
        self.registry[hdl]['request'] = req
        self.registry[hdl]['response'] = res

    def free_handler(self, hdl):
        self.active_handlers.remove(hdl)
        self.multi.remove_handle(hdl)
        self.registry[hdl]['request'] = None
        self.registry[hdl]['response'] = None
        self.idle_handlers.add(hdl)

    def handle_completed_handler(self, hdl, errno, errmsg):
        transport = self.registry[hdl]['transport']
        req = self.registry[hdl]['request']
        res = self.registry[hdl]['response']
        if errno:
            print('FAIL', req.config['url'], errno, errmsg) 
            err = build_network_error(errno, errmsg)
        else:
            #print('OK', req.config['url'], res.text[:100])
            err = None
        transport.prepare_response(req, res, err)
        self.free_handler(hdl)
        self.resultq.put({
            'request': req,
            'response': res,
        })
