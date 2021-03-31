import requests
from dateutil import parser as date_parser
from .base_provider import BaseProvider
import pytz
from time import sleep


class VirusTotalProvider(BaseProvider):
    def __init__(self, ignored_extensions, should_sort, api_key):
        super(VirusTotalProvider, self).__init__(ignored_extensions, should_sort)
        self.api_key = api_key

    def fetch_internal(self, domain):
        return self.fetch_domain_results(domain)

    def fetch_domain_results(self, domain):
        response = self.do_request(domain)
        if "undetected_urls" in response:
            for r in response["undetected_urls"]:
                yield pytz.utc.localize(date_parser.parse(r[-1])), r[0]

        if "subdomains" in response:
            for subdomain in response["subdomains"]:
                for r in self.fetch_domain_results(subdomain):
                    yield r

    def do_request(self, domain):
        throttling_message_displayed = False
        for i in range(5):
            response = requests.get('https://www.virustotal.com/vtapi/v2/domain/report', params={'apikey': self.api_key, 'domain': domain})
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 204:
                if not throttling_message_displayed:
                    print("\033[93mVirusTotal throttled. Sleeping...\033[0m")
                    throttling_message_displayed = True
                sleep(30)
            else:
                return {}

        print("\033[93mVirusTotal retry count exceeded.\033[0m")