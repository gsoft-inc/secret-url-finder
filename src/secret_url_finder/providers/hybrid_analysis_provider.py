import requests
from dateutil import parser as date_parser
from .base_provider import BaseProvider
from urllib.parse import urlparse


class HybridAnalysisProvider(BaseProvider):
    def __init__(self, ignored_extensions, should_sort, api_key):
        super(HybridAnalysisProvider, self).__init__(ignored_extensions, should_sort)
        self.api_key = api_key

    def fetch_internal(self, domain):
        headers = {"api-key": self.api_key, "User-Agent": "VxApi CLI Connector"}
        results = requests.post("https://www.hybrid-analysis.com/api/v2/search/terms", headers=headers, data={"domain": domain}).json()
        job_ids = [r["job_id"] for r in results["result"]]
        if len(job_ids) == 0:
            return

        data = {}
        for i in range(len(job_ids)):
            data["hashes[%d]" % i] = job_ids[i]
        results = requests.post("https://www.hybrid-analysis.com/api/v2/report/summary", headers=headers, data=data).json()
        for r in results:
            url = r["submit_name"]
            if domain in urlparse(url).netloc:
                yield date_parser.parse(r["analysis_start_time"]), url

