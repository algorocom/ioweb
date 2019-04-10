from pprint import pprint, pformat
from collections import defaultdict, deque
import time
import logging
from importlib import import_module
from threading import Thread
from copy import deepcopy
import sys
from datetime import datetime


class Stat(object):
    default_key_aliases = {
        'crawler:request-processed': 'req',
        'crawler:request-ok': 'req-ok',
        'crawler:request-retry': 'req-retry',
        'crawler:request-fail': 'req-fail',
        'crawler:request-rejected': 'req-rejected',
    }
    ignore_prefixes = (
        'http:',
        'network-error:',
    )
    def __init__(
            self,
            # logging
            speed_keys=None,
            logging_enabled=True,
            logging_interval=3,
            key_aliases=None,
            # export
            #shard_interval = 10,
            export=None,
            export_interval=5,
            # fatalq
            fatalq=None,
        ):
        # Arg: speed_keys
        if speed_keys is None:
            speed_keys = []
        elif isinstance(speed_keys, str):
            speed_keys = [speed_keys]
        self.speed_keys = speed_keys
        # Arg: logging_enabled
        self.logging_enabled = logging_enabled
        # Arg: logging_interval
        self.logging_interval = logging_interval
        # Arg: key_aliases
        self.key_aliases = deepcopy(self.default_key_aliases)
        if key_aliases:
            self.key_aliases.update(key_aliases)
        # Arg: shard_interval
        #self.shard_interval = shard_interval
        # Arg: export
        self.export_config = export
        self.export_driver = None
        if self.export_config:
            self.setup_export_driver(self.export_config)
        # Args: export_interval
        self.export_interval = export_interval
        # Arg: fatalq
        self.fatalq = fatalq

        # Logging
        self.total_counters = defaultdict(int)
        self.moment_counters = {}
        self.logging_time = 0
        if self.logging_enabled:
            self.th_logging = Thread(target=self.thread_logging)
            self.th_logging.daemon = True
            self.th_logging.start()

        # Export
        #self.shard_counters = {}
        self.th_export = None
        if self.export_driver:
            self.start_export_thread()

    def start_export_thread(self):
        if self.export_driver and not self.th_export:
            self.th_export = Thread(target=self.thread_export)
            self.th_export.daemon = True
            self.th_export.start()

        # Internal
        self.service_time = 0
        self.service_interval = 1

    def setup_export_driver(self, cfg):
        self.export_config = cfg
        mod_path, cls_name = cfg['driver'].split(':', 1)
        driver_mod = import_module(mod_path)
        driver_cls = getattr(driver_mod, cls_name)
        self.export_driver = driver_cls(
            tags=cfg.get('tags', {}),
            connect_options=cfg.get('connect_options', {})
        )
        if self.th_export:
            raise Exception('Stat export thread already created')
        else:
            self.start_export_thread()

    def build_eps_string(self, now):
        now_int = int(now)
        eps = defaultdict(int)
        interval = 30
        for ts in range(now_int - interval, now_int):
            for key in self.speed_keys:
                try:
                    eps[key] += self.moment_counters[ts][key]
                except KeyError:
                    eps[key] += 0

        ret = []
        for key, val in eps.items():
            label = self.key_aliases.get(key, key)
            val_str = '%.1f' % (val / interval)
            if val_str == '0.0' and val > 0:
                val_str = '0.0+'
            ret.append('%s: %s' % (label, val_str))
        return ', '.join(ret)

    def build_counter_string(self):
        ret = []
        for key in list(self.total_counters.keys()):
            if not key.startswith(self.ignore_prefixes):
                label = self.key_aliases.get(key, key)
                val = self.total_counters[key]
                ret.append('%s: %d' % (label, val))
        return ', '.join(ret)

    def thread_logging(self):
        try:
            while True:
                now = time.time()
                eps_str = self.build_eps_string(now)
                counter_str = self.build_counter_string()
                logging.debug('EPS: %s | TOTAL: %s', eps_str, counter_str)
                # Sleep `self.logging_interval` seconds minus time spent on logging
                sleep_time = (
                    self.logging_interval + (time.time() - now)
                )
                time.sleep(sleep_time)
        except (KeyboardInterrupt, Exception) as ex:
            if self.fatalq:
                self.fatalq.put(sys.exc_info())
            else:
                raise

    def thread_export(self):
        try:
            prev_counters = None
            while True:
                now = time.time()
                counters = deepcopy(self.total_counters)
                if prev_counters:
                    delta_counters = dict(
                        (x, counters[x] - prev_counters.get(x, 0))
                        for x in counters.keys()
                    )
                else:
                    delta_counters = counters
                prev_counters = counters
                self.export_driver.write_events([delta_counters])
                sleep_time = (
                    self.export_interval + (time.time() - now)
                )
                time.sleep(sleep_time)
        except (KeyboardInterrupt, Exception) as ex:
            if self.fatalq:
                self.fatalq.put(sys.exc_info())
            else:
                raise

    def inc(self, key, count=1):
        now_int = int(time.time())
        #shard_ts = now_int - now_int % self.shard_interval
        #shard_slot = self.shard_counters.setdefault(shard_ts, defaultdict(int))
        moment_slot = self.moment_counters.setdefault(now_int, defaultdict(int))

        moment_slot[key] += count
        #shard_slot[key] += count
        self.total_counters[key] += count


class InfluxdbExportDriver(object):
    def __init__(self, connect_options, tags):
        self.connect_options = deepcopy(connect_options)
        self.client = None
        self.tags = deepcopy(tags)
        self.database_created = False
        self.connect()

    def connect(self):
        from influxdb import InfluxDBClient

        self.client = InfluxDBClient(**self.connect_options)

    def write_events(self, events):
        from requests import RequestException

        if not self.database_created:
            self.client.create_database(self.connect_options['database'])
            self.database_created = True
        batch_size = 500
        for idx in range(0, len(events), batch_size):
            data = []
            for event in events[idx:idx + batch_size]:
                if event:
                    data.append({
                        "measurement": "crawler_counter",
                        "tags": self.tags,
                        "time": datetime.utcnow().isoformat(),
                        "fields": dict((
                            (x, y) for x, y in event.items()
                        )),
                    })
            #logging.debug('Exporting %s' % pformat(data))
            while True:
                try:
                    self.client.write_points(data)
                except RequestException:
                    logging.exception('Fail to send metrics')
                    time.sleep(1)
                    # reconnecting
                    while True:
                        try:
                            self.connect()
                        except RequestException:
                            logging.exception(
                                'Fail to reconnect to metric database'
                            )
                            time.sleep(1)
                        else:
                            break
                else:
                    break
