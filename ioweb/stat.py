from collections import defaultdict, deque
import time
import logging


class Stat(object):
    default_aliases = {
        'crawler:request-processed': 'req',
        'crawler:request-ok': 'req-ok',
        'crawler:request-retry': 'req-retry',
        'crawler:request-fail': 'req-fail',
    }
    def __init__(
            self,
            speed_keys=None,
            logging_interval=3,
            snapshot_interval=3,
            num_snapshots=20,
            aliases=None,
        ):
        if speed_keys is None:
            speed_keys = []
        elif isinstance(speed_keys, str):
            speed_keys = [speed_keys]
        self.speed_keys = speed_keys
        self.counters = defaultdict(int)
        self.snapshots = deque(maxlen=num_snapshots)
        self.snapshot_time = 0
        self.snapshot_interval = snapshot_interval
        self.logging_time = 0
        self.logging_interval = logging_interval
        self.aliases = self.default_aliases
        if aliases:
            self.aliases.update(aliases)

    def inc(self, key, count=1):
        self.counters[key] += count
        now = time.time()
        if now - self.snapshot_time > self.snapshot_interval:
            shot = {}
            for key in self.speed_keys:
                shot[key] = self.counters[key]
            self.snapshots.append((now, shot))
            self.snapshot_time = now
        if now - self.logging_time > self.logging_interval:
            rps_items = []
            if len(self.snapshots) > 1:
                last_shot = self.snapshots[-1] if self.snapshots else {}
                first_shot = self.snapshots[0] if self.snapshots else {}
                for key in self.speed_keys:
                    rps_items.append((
                        key,
                        (last_shot[1].get(key, 0) - first_shot[1].get(key, 0))
                        / (last_shot[0] - first_shot[0])
                    ))
            rps_str = ', '.join(
                '%s: %.1f' % (self.aliases.get(key, key), val) for key, val in rps_items
            )
            keys = self.counters.keys()
            counter_str = ', '.join(
                '%s: %s' % (self.aliases.get(x, x), self.counters[x]) for x in keys
            )
            logging.debug('Stat:%s [%s]', rps_str, counter_str)
            self.logging_time = now
