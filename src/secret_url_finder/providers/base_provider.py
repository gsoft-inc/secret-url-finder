from urllib.parse import urlparse, parse_qsl, urlencode, ParseResult


class BaseProvider(object):
    ignored_query_string_parameters = ["_ga", "__gda__", "_gac", "gclid", "msclkid", "_hsenc", "_hsmi", "mkt_tok", "ref"]
    ignored_query_string_prefixes = ["utm_"]

    def __init__(self, ignored_extensions, should_sort):
        self.ignored_extensions = ignored_extensions
        self.should_sort = should_sort

    def fetch(self, domain):
        results = self.fetch_internal(domain)
        results = self.filter_extensions(results)
        results = self.sort(results)
        results = self.remove_common_parameters(results)
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

    def remove_common_parameters(self, results):
        for time, url in results:
            url_modified = False
            parsed = urlparse(url)
            args = dict(parse_qsl(parsed.query))

            for param in list(args.keys()):
                lower_param = param.lower()
                if any([lower_param.startswith(prefix) for prefix in self.ignored_query_string_prefixes]) or lower_param in self.ignored_query_string_parameters:
                    url_modified = True
                    del args[param]

            if url_modified:
                encoded_args = urlencode(args, doseq=True)
                url = ParseResult(parsed.scheme, parsed.netloc, parsed.path, parsed.params, encoded_args, parsed.fragment).geturl()

            yield time, url
