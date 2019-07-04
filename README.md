## IOWeb Framework

Python framework to build web crawlers.

What we have at the moment:

 * system designed to run large number network threads (like 100 or 500) on
    on CPU core
 * built-in feature to combine things in chunks and then doing something with
    chunks (like mongodb bulk write)
 * asynchronous things are powered by gevent
 * network requests are handled with urllib3
 * built-in stat module to count events, built-in logging into influxdb
 * retrying on errors
 * no tests
 * no documentation

I am using ioweb to do bulk web scraping like crawling 500M pages in few days.


## Places to talk

 * https://t.me/grablab - English speaking chat about web scraping
 * https://t.me/grablab\_ru - Russian speaking chat about web scraping
