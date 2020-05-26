from urllib.parse import urlparse


class BaseProvider(object):

    def __init__(self, ignored_extensions, should_sort):
        self.ignored_extensions = ignored_extensions
        self.should_sort = should_sort

    def fetch(self, domain):
        results = self.fetch_internal(domain)
        results = self.filter_extensions(results)
        results = self.sort(results)
        return results

    def sort(self, results):
        if self.should_sort:
            return sorted(results, key=lambda x: x[0], reverse=True)
        else:
            return results

    def fetch_internal(self, domain):
        return []

    def filter_extensions(self, results):
        for time, url in results:
            last_part = urlparse(url).path.split("/")[-1].lower()
            if any(ext for ext in self.ignored_extensions if last_part.endswith("." + ext)):
                continue
            yield time, url