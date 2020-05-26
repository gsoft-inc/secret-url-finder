from providers.base_provider import BaseProvider
import requests
from dateutil import parser as date_parser
from util import merge_results
import pytz


class AlienVaultOTXProvider(BaseProvider):
    def __init__(self, ignored_extensions, should_sort):
        super(AlienVaultOTXProvider, self).__init__(ignored_extensions, should_sort)

    def fetch_internal(self, domain):
        return merge_results(self.should_sort, self.request(domain, "domain"), self.request(domain, "hostname"))

    def sort(self, results):
        return results  # Results are already sorted.

    @staticmethod
    def request(domain, endpoint):
        page = 1
        while True:
            result = requests.get("https://otx.alienvault.com/otxapi/indicator/%s/url_list/%s?limit=50&page=%d" % (endpoint, domain, page)).json()
            for r in result["url_list"]:
                yield pytz.utc.localize(date_parser.parse(r["date"])), r["url"]
            if not result["has_next"]:
                break
            page += 1