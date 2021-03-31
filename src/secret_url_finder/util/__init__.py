import heapq
import datetime
import pytz


def merge_results(should_sort, *results):
    # Reverses the time to sort results from most recent to oldest.
    def wrap(results):
        for time, url in results:
            yield pytz.utc.localize(datetime.datetime.max) - time, time, url

    if should_sort:
        for offset, time, url in heapq.merge(*[wrap(r) for r in results]):
            yield time, url
    else:
        for r in results:
            for x in r:
                yield x