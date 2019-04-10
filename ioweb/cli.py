from gevent import monkey
monkey.patch_all()#thread=False)

try:
    import grpc
except ImportError:
    pass
else:
    if grpc.__version__ != '1.18.0':
        raise Exception('grpcio version must be 1.18.0')
    from grpc.experimental import gevent
    gevent.init_gevent()

import sys
import re
import time
import os.path
import json
import logging
from argparse import ArgumentParser

#import crawler
from .crawler import Crawler

logger = logging.getLogger('crawler.cli')


def find_crawlers_in_module(mod, reg):
    for key in dir(mod):
        val = getattr(mod, key)
        if (
                isinstance(val, type)
                and issubclass(val, Crawler)
                and val is not Crawler
            ):
            logger.debug(
                'Found crawler %s in module %s',
                val.__name__, mod.__file__
            )
            reg[val.__name__] = val


def collect_crawlers():
    reg = {}

    # Give crawlers in current directory max priority
    # Otherwise `/web/crawler/crawlers` packages are imported
    # when crawler is installed with `pip -e /web/crawler`
    sys.path.insert(0, os.getcwd())

    for location in ('crawlers',):
        try:
            mod = __import__(location, None, None, ['foo'])
        except ImportError as ex:
            #if path not in str(ex):
            logger.exception('Failed to import %s', location)
        else:
            if mod.__file__.endswith('__init__.py'):
                dir_ = os.path.split(mod.__file__)[0]
                for fname in os.listdir(dir_):
                    if (
                        fname.endswith('.py')
                        and not fname.endswith('__init__.py')
                    ):
                        target_mod = '%s.%s' % (location, fname[:-3])
                        try:
                            mod = __import__(target_mod, None, None, ['foo'])
                        except ImportError as ex:
                            #if path not in str(ex):
                            logger.exception('Failed to import %s', target_mod)
                        else:
                            find_crawlers_in_module(mod, reg)
            else:
                find_crawlers_in_module(mod, reg)

    return reg


def setup_logging(network_logs=False):#, control_logs=False):
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('urllib3.connectionpool').setLevel(level=logging.ERROR)
    logging.getLogger('ioweb.urllib3_custom').setLevel(level=logging.ERROR)
    if not network_logs:
        logging.getLogger('ioweb.network_service').propagate = False
    #if not control_logs:
    #    logging.getLogger('crawler.control').propagate = False


def format_elapsed_time(total_sec):
    hours = minutes = 0
    if total_sec > 3600:
        hours, total_sec = divmod(total_sec, 3600)
    if total_sec > 60:
        minutes, total_sec = divmod(total_sec, 60)
    return '%02d:%02d:%.2f' % (hours, minutes, total_sec)


def get_crawler(crawler_id):
    reg = collect_crawlers()
    if crawler_id not in reg:
        sys.stderr.write(
            'Could not load %s crawler\n' % crawler_id
        )
        sys.exit(1)
    else:
        return reg[crawler_id]


def run_command_crawl():
    parser = ArgumentParser()
    parser.add_argument('crawler_id')
    parser.add_argument('-t', '--network-threads', type=int, default=1)
    parser.add_argument('-n', '--network-logs', action='store_true', default=False)
    parser.add_argument('-p', '--profile', action='store_true', default=False)
    #parser.add_argument('--control-logs', action='store_true', default=False)
    opts = parser.parse_args()

    setup_logging(network_logs=opts.network_logs)#, control_logs=opts.control_logs)

    cls = get_crawler(opts.crawler_id)
    bot = cls(
        network_threads=opts.network_threads,
    )
    try:
        if opts.profile:
            import cProfile
            import pyprof2calltree
            import pstats

            profile_file = 'var/%s.prof' % opts.crawler_id
            profile_tree_file = 'var/%s.prof.out' % opts.crawler_id

            prof = cProfile.Profile()
            try:
                prof.runctx('bot.run()', globals(), locals())
            finally:
                stats = pstats.Stats(prof)
                stats.strip_dirs()
                pyprof2calltree.convert(stats, profile_tree_file)
        else:
            bot.run()
    except KeyboardInterrupt:
        pass
    print('Stats:')
    for key, val in sorted(bot.stat.total_counters.items()):
        print(' * %s: %s' % (key, val))
    if bot._run_started:
        print('Elapsed: %s' % format_elapsed_time(time.time() - bot._run_started))
    else:
        print('Elapsed: NA')
