import requests
from dateutil import parser as date_parser
from .base_provider import BaseProvider
import pytz


class WaybackMachineProvider(BaseProvider):
    def __init__(self, ignored_extensions, should_sort):
        super(WaybackMachineProvider, self).__init__(ignored_extensions, should_sort)

    def fetch_internal(self, domain):
        wb_url = "http://web.archive.org/cdx/search/cdx?url=%s/&matchType=domain&collapse=urlkey&showResumeKey=true&limit=10000&fl=timestamp,original" % domain
        resume_key = None
        while True:
            has_resume_key = False
            lines = requests.get(
                wb_url if not resume_key else "%s&resumeKey=%s" % (wb_url, resume_key)).text.splitlines(False)
            for line in lines:
                if has_resume_key:
                    resume_key = line
                    continue

                if line:
                    timestamp, url = line.split(" ", 1)
                    yield pytz.utc.localize(date_parser.parse(timestamp)), url
                else:
                    has_resume_key = True

            if not has_resume_key:
                break
