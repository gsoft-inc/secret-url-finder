from urllib.parse import urlparse
import requests
from dateutil import parser as date_parser
from providers.base_provider import BaseProvider


class UrlScanProvider(BaseProvider):
    request_size = 1000

    def __init__(self, ignored_extensions):
        super(UrlScanProvider, self).__init__(ignored_extensions, False)  # Results are already sorted.

    def fetch_internal(self, domain):
        params = {
            "q": f"domain:{domain}",
            "sort_field": "date",
            "sort_order": "desc",
            "size": self.request_size
        }
        while True:
            results = requests.get("https://urlscan.io/api/v1/search/", params=params).json()["results"]
            for result in results:
                url = result["page"]["url"]
                time = date_parser.parse(result["task"]["time"])
                if domain in urlparse(url).netloc:
                    yield time, url

                for url in requests.get(result["result"]).json()["lists"]["urls"]:
                    if domain in urlparse(url).netloc:
                        yield time, url

            if len(results) < self.request_size:
                break

            params["search_after"] = ",".join(str(v) for v in results[-1]["sort"])
