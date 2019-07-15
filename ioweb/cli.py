from pprint import pprint
import sys
import re
import time
import os.path
import json
import logging
from argparse import ArgumentParser

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
            logger.error(
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
            'Could not find %s crawler\n' % crawler_id
        )
        sys.exit(1)
    else:
        return reg[crawler_id]


def run_subcommand_crawl(opts):
    setup_logging(network_logs=opts.network_logs)#, control_logs=opts.control_logs)
    cls = get_crawler(opts.crawler_id)
    extra_data = {}
    for key in cls.extra_cli_args():
        opt_key = 'extra_%s' % key.replace('-', '_')
        extra_data[key] = getattr(opts, opt_key)
    bot = cls(
        network_threads=opts.network_threads,
        extra_data=extra_data,
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
        bot.fatal_error_happened.set()
    print('Stats:')
    for key, val in sorted(bot.stat.total_counters.items()):
        print(' * %s: %s' % (key, val))
    if bot._run_started:
        print('Elapsed: %s' % format_elapsed_time(time.time() - bot._run_started))
    else:
        print('Elapsed: NA')
    if bot.fatal_error_happened.is_set():
        sys.exit(1)
    else:
        sys.exit(0)


def run_subcommand_foo(parser, opts):
    print('COMMAND FOO')


def command_ioweb():
    parser = ArgumentParser()#add_help=False)

    crawler_cls = None
    if len(sys.argv) > 2:
        if sys.argv[1] == 'crawl':
            crawler_cls = get_crawler(sys.argv[2])

    subparsers = parser.add_subparsers(
        dest='command',
        title='Subcommands of ioweb command',
        description='',
    )

    # Crawl
    crawl_subparser = subparsers.add_parser(
        'crawl', help='Run crawler',
    )
    crawl_subparser.add_argument('crawler_id')
    crawl_subparser.add_argument('-t', '--network-threads', type=int, default=1)
    crawl_subparser.add_argument('-n', '--network-logs', action='store_true', default=False)
    crawl_subparser.add_argument('-p', '--profile', action='store_true', default=False)
    #parser.add_argument('--control-logs', action='store_true', default=False)
    if crawler_cls:
        crawler_cls.update_arg_parser(crawl_subparser)

    # Foo
    foo_subparser = subparsers.add_parser(
        'foo', help='Just test subcommand',
    )

    opts = parser.parse_args()
    if opts.command == 'crawl':
        run_subcommand_crawl(opts)
    else:
        if opts.command == 'foo':
            run_subcommand_foo(opts)
        else:
            parser.print_help()
