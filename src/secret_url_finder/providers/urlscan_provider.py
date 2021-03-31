from urllib.parse import urlparse
import requests
from dateutil import parser as date_parser
from .base_provider import BaseProvider
from datetime import datetime, timedelta, timezone
import dateutil.parser
import time


class UrlScanProvider(BaseProvider):
    request_size = 1000
    _rate_limiting = {}

    def __init__(self, api_key, ignored_extensions):
        super(UrlScanProvider, self).__init__(ignored_extensions, False)  # Results are already sorted.
        reset_time = datetime.now(timezone.utc) + timedelta(minutes=1)
        self._rate_limiting["search"] = {"remaining": 1, "reset_time": reset_time}
        self._rate_limiting["results"] = {"remaining": 1, "reset_time": reset_time}

        self.headers = {}
        if api_key:
            self.headers["API-Key"] = api_key

    def fetch_internal(self, domain):
        params = {
            "q": f"domain:{domain}",
            "sort_field": "date",
            "sort_order": "desc",
            "size": self.request_size
        }
        while True:
            results = self.request("search", "https://urlscan.io/api/v1/search/", params).json()["results"]
            for result in results:
                url = result["page"]["url"]
                time = date_parser.parse(result["task"]["time"])
                if domain in urlparse(url).netloc:
                    yield time, url

                for url in self.request("results", result["result"]).json()["lists"]["urls"]:
                    if domain in urlparse(url).netloc:
                        yield time, url

            if len(results) < self.request_size:
                break

            params["search_after"] = ",".join(str(v) for v in results[-1]["sort"])

    def request(self, rate_key, url, params=None):
        rate_limiting = self._rate_limiting[rate_key]
        while True:
            if rate_limiting["remaining"] == 0:
                sleep_duration = (rate_limiting["reset_time"] - datetime.now(timezone.utc)).total_seconds()
                if sleep_duration < 0:
                    sleep_duration = 1
                time.sleep(sleep_duration)

            response = requests.get(url, params=params, headers=self.headers)
            rate_limiting["remaining"] = int(response.headers["X-Rate-Limit-Remaining"])
            rate_limiting["reset_time"] = dateutil.parser.isoparse(response.headers["X-Rate-Limit-Reset"])

            if response.status_code != 429:
                return response
