import pytz
from providers.base_provider import BaseProvider
import requests
from dateutil import parser as date_parser
import time
import json


class CommonCrawlProvider(BaseProvider):
    def __init__(self, ignored_extensions):
        super(CommonCrawlProvider, self).__init__(ignored_extensions, False)  # Results are already sorted.

    def fetch_internal(self, domain):
        urls = set()
        for index in self.fetch_indexes():
            response = self.request("%s?output=json&matchType=domain&url=%s" % (index, domain))
            if response:
                json_results = [json.loads(l) for l in response.text.splitlines(False)]
                results = [(pytz.utc.localize(date_parser.parse(j["timestamp"])), j["url"]) for j in json_results]
                for time, url in sorted(results, key=lambda x: x[0], reverse=True):
                    if url in urls:
                        continue
                    urls.add(url)
                    yield time, url

    def fetch_indexes(self):
        response = self.request("http://index.commoncrawl.org/collinfo.json")
        if response:
            for r in response.json():
                yield r["cdx-api"]
        else:
            print("\033[93mCould not fetch CommonCrawl indexes.\033[0m")

    def request(self, url):
        for i in range(1, 5):
            r = requests.get(url)
            if r.status_code == 200:
                return r
            if r.status_code == 404:
                return None

            sleep_time = i * 5
            print("\033[93mError when querying CommonCrawl. Sleeping %d seconds...\033[0m" % sleep_time)
            time.sleep(sleep_time)
        return None
