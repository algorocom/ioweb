import time
import sys
import logging
from threading import Event, Thread, Lock
from queue import Queue, PriorityQueue, Empty, Full
from urllib.parse import urlsplit 
import re
import json
from urllib.request import urlopen
from traceback import format_exception
from collections import defaultdict
import gc

import greenlet
import gevent
from .util import Pause, debug
#from .loop import MultiCurlLoop
from .network_service import NetworkService
from .stat import Stat
from .request import Request


class Crawler(object):
    _taskgen_sleep_time = 0.01
    dataop_threshold_default = {
        'number': 500,
        'size': None,
        #'time': None,
    }
    dataop_threshold = {}

    def task_generator(self):
        if False:
            yield None

    def __init__(self,
            network_threads=3,
            result_workers=4,
            retry_limit=3,
        ):
        self.taskq = PriorityQueue()
        self.taskq_size_limit = max(100, network_threads * 2)
        self.resultq = Queue()
        self.shutdown_event = Event()
        self.network_pause = Pause()
        self.retry_limit = retry_limit
        self.stat = Stat(speed_keys='crawler:request-processed')
        self.fatalq = Queue()
        self.network = NetworkService(
            self.taskq, self.resultq,
            threads=network_threads,
            shutdown_event=self.shutdown_event,
            pause=self.network_pause,
            setup_handler_hook=self.setup_handler_hook,
            stat=self.stat,
        )
        self.result_workers = result_workers
        self._run_started = None

        self.dataopq = {}
        self.dataop_lock = defaultdict(Lock)
        self.dataop_counters = defaultdict(lambda: {
            'number': 0,
            'size': 0,
        })

        self.init_hook()

    def is_dataopq_dump_time(self, name):
        to_dump = False
        try:
            number_th = self.dataop_threshold[name]['number']
        except KeyError:
            number_th = self.dataop_threshold_default['number']
        if number_th:
            if self.dataop_counters[name]['number'] >= number_th:
                    to_dump = True
        if not to_dump:
            try:
                size_th = self.dataop_threshold[name]['size']
            except KeyError:
                size_th = self.dataop_threshold_default['size']
            if size_th:
                if self.dataop_counters[name]['size'] >= size_th:
                    to_dump = True
        return to_dump

    def enq_dataop(self, name, op, size=None, force_dump=False):
        self.dataop_lock[name].acquire()
        released = False
        try:
            self.dataopq.setdefault(name, [])
            if op:
                self.dataopq[name].append(op)
                self.dataop_counters[name]['number'] += 1
                if size:
                    self.dataop_counters[name]['size'] += size

            if force_dump or self.is_dataopq_dump_time(name):
                logging.debug('Dumping data ops')
                ops = self.dataopq[name]
                self.dataopq[name] = []
                self.dataop_counters[name]['number'] = 0
                self.dataop_counters[name]['size'] = 0
                self.dataop_lock[name].release()
                released = True
                func = getattr(self, 'dataop_handler_%s' % name)
                func(ops)
        finally:
            if not released:
                self.dataop_lock[name].release()


    def init_hook(self):
        pass

    def setup_handler_hook(self, transport, req):
        pass

    def submit_task(self, req):
        self.submit_task_hook(req)
        self.taskq.put((req.priority, req))

    def submit_task_hook(self, req):
        pass

    def thread_task_generator(self):
        try:
            for item in self.task_generator():
                while item:
                    if self.shutdown_event.is_set():
                        return
                    if self.taskq.qsize() >= self.taskq_size_limit:
                        time.sleep(self._taskgen_sleep_time)
                    else:
                        self.submit_task(item)
                        item = None
        except (KeyboardInterrupt, Exception) as ex:
            self.fatalq.put(sys.exc_info())

    def is_result_ok(self, req, res):
        if res.error:
            return False
        elif (
                0 < res.status < 400
                or res.status == 404
                or (
                    req.config['extra_valid_status']
                    and res.status in req.config['extra_valid_status']
                )
            ):
            return True
        else:
            return False

    def thread_result_processor(self, pause):
        try:
            while not self.shutdown_event.is_set():
                if pause.pause_event.is_set():
                    pause.process_pause()
                try:
                    result = self.resultq.get(True, 0.1)
                except Empty:
                    pass
                else:
                    self.stat.inc('crawler:request-processed')
                    if (
                            result['request']['raw']
                            or self.is_result_ok(
                                result['request'],
                                result['response'],
                            )
                        ):
                        self.process_ok_result(result)
                    else:
                        self.process_fail_result(result)
        except (KeyboardInterrupt, Exception) as ex:
            self.fatalq.put(sys.exc_info())

    def thread_fatalq_processor(self):
        while not self.shutdown_event.is_set():
            try:
                etype, evalue, tb = self.fatalq.get(True, 0.1)
            except Empty:
                pass
            else:
                self.shutdown_event.set()
                logging.error('Fatal exception')
                logging.error(''.join(format_exception(etype, evalue, tb)))

    def thread_manager(self, th_task_gen, pauses):
        try:
            th_task_gen.join()

            def system_is_busy():
                return (
                    self.taskq.qsize()
                    or self.resultq.qsize()
                    or len(self.network.active_handlers)
                )

            while not self.shutdown_event.is_set():
                while system_is_busy():
                    if self.shutdown_event.is_set():
                        return
                    time.sleep(0.1)

                for pause in pauses:
                    pause.pause_event.set()
                ok = True
                for pause in pauses:
                    if not pause.is_paused.wait(0.1):
                        ok = False
                        break
                if not ok:
                    for pause in pauses:
                        pause.pause_event.clear()
                        pause.resume_event.set()
                else:
                    if not system_is_busy():
                        for pause in pauses:
                            pause.pause_event.clear()
                            pause.resume_event.set()
                        self.shutdown_event.set()
                        return
        except (KeyboardInterrupt, Exception) as ex:
            self.fatalq.put(sys.exc_info())

    def process_ok_result(self, result):
        self.stat.inc('crawler:request-ok')
        name = result['request'].config['name']
        handler = getattr(self, 'handler_%s' % name)
        handler_result = handler(
            result['request'],
            result['response'],
        )
        try:
            iter(handler_result)
        except TypeError:
            pass
        else:
            for item in handler_result:
                print('Processing handler result: %s' % item)

    def process_fail_result(self, result):
        self.stat.inc('crawler:request-fail')
        req = result['request']

        if result['response'].error:
            self.stat.inc('network-error:%s' % result['response'].error.get_tag())
        if result['response'].status:
            self.stat.inc('http:status-%s' % result['response'].status)

        if req.retry_count + 1 <= self.retry_limit:
            self.stat.inc('crawler:request-retry')
            req.retry_count += 1
            req.priority = req.priority - 1
            self.submit_task(req)
        else:
            self.stat.inc('crawler:request-rejected')
            name = result['request'].config['name']
            handler = getattr(self, 'rejected_%s' % name, None)
            if handler is None:
                handler = self.default_rejected_handler
            handler(result['request'], result['response'])

    def default_rejected_handler(self, req, res):
        pass

    def run_hook(self):
        pass

    def thread_stat(self):
        try:
            while not self.shutdown_event.is_set():
                stat = []
                now = time.time()
                for hdl in self.network.active_handlers:
                    stat.append((hdl, self.network.registry[hdl]['start']))
                with open('var/crawler.stat', 'w') as out:
                    for hdl, start in list(sorted(stat, key=lambda x: (x[1] or now), reverse=True)):
                        req = self.network.registry[hdl]['request']
                        out.write('%.2f - [#%s] - %s\n' % (
                            (now - start) if start else 0,
                            req.retry_count if req else 'NA',
                            urlsplit(req['url']).netloc if req else 'NA',
                        ))
                    out.write('Active handlers: %d\n' % len(self.network.active_handlers))
                    out.write('Idle handlers: %d\n' % len(self.network.idle_handlers))
                    out.write('Taskq size: %d\n' % self.taskq.qsize())
                    out.write('Resultq size: %d\n' % self.resultq.qsize())

                total = 0
                count = 0
                for hdl, start in stat:
                    if start:
                        total += (now - start)
                        count += 1
                logging.debug('Median handler time: %.2f' % ((total / count) if count else 0))

                self.shutdown_event.wait(3)
        except (KeyboardInterrupt, Exception) as ex:
            self.fatalq.put(sys.exc_info())


    def thread_network(self):
        try:
            self.network.run()
        except (KeyboardInterrupt, Exception) as ex:
            self.fatalq.put(sys.exc_info())

    def shutdown(self):
        for name in self.dataopq.keys():
            self.enq_dataop(name, None, force_dump=True)
        self.shutdown_hook()

    def shutdown_hook(self):
        pass

    def run(self):
        self.run_hook()
        try:
            self._run_started = time.time()

            th_fatalq_proc = Thread(target=self.thread_fatalq_processor)
            th_fatalq_proc.start()

            th_task_gen = Thread(target=self.thread_task_generator)
            th_task_gen.start()

            #th_stat = Thread(target=self.thread_stat)
            #th_stat.start()

            pauses = [self.network_pause]
            result_workers = []
            for _ in range(self.result_workers):
                pause = Pause()
                th = Thread(
                    target=self.thread_result_processor,
                    args=[pause],
                ) 
                pauses.append(pause)
                th.start()
                result_workers.append(th)

            th_manager = Thread(
                target=self.thread_manager,
                args=[th_task_gen, pauses],
            )
            th_manager.start()


            th_network = Thread(
                target=self.thread_network,
            )
            th_network.start()

            try:
                th_manager.join()
                th_fatalq_proc.join()
                th_task_gen.join()
                #th_stat.join()
                [x.join() for x in result_workers]
            except KeyboardInterrupt:
                self.shutdown_event.set()

        finally:
            self.shutdown()

            ## Wait all thread completes working or
            ## kill if it takes more than 1 second
            #try:
            #    th_manager.join(1)
            #    th_fatalq_proc.join(1)
            #    th_task_gen.join(1)
            #    th_stat.join(1)
            #    [x.join(1) for x in result_workers]
            #except NameError:
            #    # Inside finally block not all objects might exist
            #    pass

            ## Now just kill every greenlet
            ## Becase of magic nature of gevent
            ## some libraries like grpcio can not work
            ## well with SIGINT signal
            #current_greenlet = gevent.getcurrent()
            #gevent.killall([
            #        x for x in gc.get_objects()
            #        if isinstance(x, greenlet.greenlet) and x is not current_greenlet
            #    ], timeout=1)
            #print('called killall()')
