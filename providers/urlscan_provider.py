from providers.base_provider import BaseProvider
import requests
from dateutil import parser as date_parser
from urllib.parse import urlparse


class UrlScanProvider(BaseProvider):
    def __init__(self, ignored_extensions):
        super(UrlScanProvider, self).__init__(ignored_extensions, False)  # Results are already sorted.

    def fetch_internal(self, domain):
        offset = 0

        while True:
            results = requests.get("https://urlscan.io/api/v1/search/?q=domain%3A%22" + domain + "%22&offset=" + str(offset) + "&sort_field=date&sort_order=desc").json()["results"]
            for result in results:
                url = result["page"]["url"]
                time = date_parser.parse(result["task"]["time"])
                if domain in urlparse(url).netloc:
                    yield time, url

                for url in requests.get(result["result"]).json()["lists"]["urls"]:
                    if domain in urlparse(url).netloc:
                        yield time, url

            if len(results) < 100:
                break

            offset += 100