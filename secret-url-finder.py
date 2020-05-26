#!/usr/bin/env python3
import argparse
from providers import create_providers
from util import merge_results
from util.secrets import calculate_url_score


if __name__ == "__main__":
    default_ignored_extensions = "gif,jpg,png,css,svg,woff,woff2"
    parser = argparse.ArgumentParser(description='Find secret URLs.')
    parser.add_argument('--domain', help='The domain to search', required=True)
    parser.add_argument('-f', '--filter', help='Only show URLs with secrets', action='store_true')
    parser.add_argument('-s', '--sorted', help='Sort results from newest to oldest', action='store_true')
    parser.add_argument('-u', '--url-only', help='Only displays the URLs.', action='store_true')
    parser.add_argument('--hybrid-analysis-key', help='The API key for hybrid analysis')
    parser.add_argument('--virus-total-key', help='The API key for VirusTotal')
    parser.add_argument('--ignored-extensions', help='File extensions to ignore. Defaults to: "%s"' % default_ignored_extensions, default=default_ignored_extensions)
    args = parser.parse_args()

    urls = set()
    providers = create_providers([ext.lower() for ext in args.ignored_extensions.split(",")], args.sorted, args.hybrid_analysis_key, args.virus_total_key)
    generators = [provider.fetch(args.domain) for provider in providers]
    for time, url in merge_results(args.sorted, *generators):
        if url in urls:
            continue

        urls.add(url)
        if args.url_only:
            line = url
        else:
            line = "%s - %s" % (str(time), url)

        if calculate_url_score(url) >= 100:
            print("\033[91m%s\033[0m" % line)
        elif not args.filter:
            print(line)

