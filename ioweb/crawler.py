import time
from threading import Event, Thread
from queue import Queue, Empty, Full

from .util import Pause, debug
from .loop import MultiCurlLoop
from .stat import Stat


class Crawler(object):
    def task_generator(self):
        if False:
            yield None

    def __init__(self,
            network_threads=3,
            result_workers=4,
            retry_limit=3,
        ):
        self.taskq = Queue()
        self.taskq_size_limit = network_threads * 2
        self.resultq = Queue()
        self.shutdown_event = Event()
        self.loop_pause = Pause()
        self.retry_limit = retry_limit
        self.loop = MultiCurlLoop(
            self.taskq, self.resultq,
            threads=network_threads,
            shutdown_event=self.shutdown_event,
            pause=self.loop_pause,
        )
        self.result_workers = result_workers
        self.stat = Stat(speed_keys='crawler:request-processed')

    def thread_task_generator(self):
        for item in self.task_generator():
            while item:
                if self.taskq.qsize() >= self.taskq_size_limit:
                    time.sleep(0.1)
                else:
                    self.taskq.put(item)
                    item = None

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

    def thread_manager(self, th_task_gen, pauses):
        th_task_gen.join()

        def system_is_busy():
            return (
                self.taskq.qsize()
                or self.resultq.qsize()
                or len(self.loop.active_handlers)
            )

        while True:
            #debug('-- thread_manager: start loop')
            # wait till nothing is busy
            while system_is_busy():
                #debug('-- thread manager: system is busy')
                #debug('-- thread_manager: taskq.qsize = %d', self.taskq.qsize())
                #debug('-- thread_manager: resultq.qsize = %d', self.resultq.qsize())
                #debug('-- thread_manager: loop.active_handlers = %d', len(self.loop.active_handlers))
                time.sleep(0.5)

            for pause in pauses:
                pause.pause_event.set()
            ok = True
            for pause in pauses:
                if not pause.is_paused.wait(0.5):
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
                    print('SHUTDOWN SIGNALS IS SET')
                    self.shutdown_event.set()
                    return

    def process_ok_result(self, result):
        self.stat.inc('crawler:request-ok')
        name = result['request'].config['name']
        handler = getattr(self, 'handler_%s' % name)
        # TODO: curl have to put response data in Response object
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
        req = result['request']
        if req.retry_count + 1 <= self.retry_limit:
            self.stat.inc('crawler:request-retry')
            req.retry_count += 1
            self.taskq.put(req)
        else:
            self.stat.inc('crawler:request-fail')
            name = result['request'].config['name']
            print('[FAIL] request to %s' % result['request'].config['url'])

    def prepare(self):
        pass

    def run(self):
        self.prepare()

        th_task_gen = Thread(target=self.thread_task_generator)
        th_task_gen.start()

        pauses = [self.loop_pause]
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

        # `loop.run` is stopped by `th_manager`
        self.loop.run()
