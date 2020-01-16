#!/usr/bin/env python3
import requests
from urllib.parse import urlparse, parse_qs
import re
from dateutil import parser as date_parser
import math
import string
import argparse
import heapq
import pytz
import datetime
from time import sleep


ignored_query_string_parameters = ["_ga", "__gda__", "_gac", "gclid", "msclkid", "_hsenc", "mkt_tok"]
ignored_query_string_prefixes = ["utm_"]

def compile_re(s):
    return re.compile(r"^" + s + r"$", re.IGNORECASE)


SECRET_REGEX = {
    compile_re("'^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z'"): ["UUID"],
    compile_re(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)'): ["base64"],
    compile_re(r"[a-f0-9]{32}(:.+)?"):  ["MD5", "MD4", "MD2", "Double MD5", "LM", "RIPEMD-128", "Haval-128", "Tiger-128", "Skein-256(128)", "Skein-512(128", "Lotus Notes/Domino 5", "Skype", "ZipMonster", "PrestaShop"],
    compile_re(r"[a-f0-9]{64}(:.+)?"):  ["SHA-256", "RIPEMD-256", "SHA3-256", "Haval-256", "GOST R 34.11-94", "GOST CryptoPro S-Box", "Skein-256", "Skein-512(256)", "Ventrilo"],
    compile_re(r"[a-f0-9]{128}(:.+)?"): ["SHA-512", "Whirlpool", "Salsa10", "Salsa20", "SHA3-512", "Skein-512", "Skein-1024(512)"],
    compile_re(r"[a-f0-9]{56}"):        ["SHA-224", "Haval-224", "SHA3-224", "Skein-256(224)", "Skein-512(224)"],
    compile_re(r"[a-f0-9]{40}(:.+)?"):  ["SHA-1", "Double SHA-1", "RIPEMD-160", "Haval-160", "Tiger-160", "HAS-160", "LinkedIn", "Skein-256(160)", "Skein-512(160)", "MangoWeb Enhanced CMS"],
    compile_re(r"[a-f0-9]{96}"):        ["SHA-384", "SHA3-384", "Skein-512(384)", "Skein-1024(384)"],
    compile_re(r"[a-f0-9]{16}"):        ["MySQL323", "DES(Oracle)", "Half MD5", "Oracle 7-10g", "FNV-164", "CRC-64"],
    compile_re(r"\*[a-f0-9]{40}"):      ["MySQL5.x", "MySQL4.1"],
    compile_re(r"[a-f0-9]{48}"):        ["Haval-192", "Tiger-192", "SHA-1(Oracle)", "XSHA (v10.4 - v10.6)"]
}


def is_secret(check_hash):
    check_hash = check_hash.replace("-", "").replace("_", "")
    for algorithm, items in SECRET_REGEX.items():
        if algorithm.match(check_hash):
            return True
    return False


def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in (ord(c) for c in string.printable):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def calculate_url_score(url):
    score = 1
    parsed = urlparse(url)
    parts = parsed.netloc.split(".")
    parts.extend([p for p in parsed.path.split("/") if p])

    splitted_last_part = parts[-1].lower().split(".", 1)
    if len(splitted_last_part) > 1:
        if splitted_last_part[1] in ["js", "css"]:
            return 1

    for part in parts:
        if is_secret(part):
            score += 100

    qs = parse_qs(parsed.query)
    if parsed.query and len(qs.items()) == 0:
        qs[""] = [parsed.query]
    for k, value in qs.items():
        k = k.lower()
        value = value[0]
        if any([k.startswith(prefix) for prefix in ignored_query_string_prefixes]) or k in ignored_query_string_parameters:
            continue

        if urlparse(value).netloc:
            score += calculate_url_score(value)
        elif "id" in k or "token" in k or is_secret(value) or calculate_entropy(value) > 3:
            score += 100

    return score


def merge_results(should_sort, *results):
    # Reverses the time to sort results from most recent to oldest.
    def wrap(results):
        for time, url in results:
            yield pytz.utc.localize(datetime.datetime.max) - time, time, url

    if should_sort:
        for offset, time, url in heapq.merge(*[wrap(r) for r in results]):
            yield time, url
    else:
        for r in results:
            for x in r:
                yield x


def scan_alienvault(domain, should_sort):
    def request(endpoint):
        page = 1
        while True:
            result = requests.get("https://otx.alienvault.com/otxapi/indicator/%s/url_list/%s?limit=50&page=%d" % (endpoint, domain, page)).json()
            for r in result["url_list"]:
                yield pytz.utc.localize(date_parser.parse(r["date"])), r["url"]
            if not result["has_next"]:
                break
            page += 1

    return merge_results(should_sort, request("domain"), request("hostname"))


def scan_urlscan(domain):
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


def scan_hybrid_analysis(domain, api_key):
    results = requests.post("https://www.hybrid-analysis.com/api/v2/search/terms", headers={"api-key": api_key, "User-Agent": "VxApi CLI Connector"}, data={"domain": domain}).json()
    job_ids = [r["job_id"] for r in results["result"]]
    data = {}
    for i in range(len(job_ids)):
        data["hashes[%d]" % i] = job_ids[i]
    results = requests.post("https://www.hybrid-analysis.com/api/v2/report/summary", headers={"api-key": api_key, "User-Agent": "VxApi CLI Connector"}, data=data).json()
    for r in results:
        url = r["submit_name"]
        if domain in urlparse(url).netloc:
            yield date_parser.parse(r["analysis_start_time"]), url


class VirusTotalRequester(object):
    def __init__(self, api_key):
        self.api_key = api_key

    def request(self, domain):
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


def scan_virus_total(domain, requester, should_sort):
    def do_scan(domain):
        response = requester.request(domain)
        if "undetected_urls" in response:
            for r in response["undetected_urls"]:
                yield pytz.utc.localize(date_parser.parse(r[-1])), r[0]

        if "subdomains" in response:
            for subdomain in response["subdomains"]:
                for r in do_scan(subdomain):
                    yield r

    results = do_scan(domain)
    if should_sort:
        results = sorted(results, key=lambda t: t[0], reverse=True)
    for r in results:
        yield r


def scan_all(domain, should_sort, hybrid_analysis_key, virus_total_key):
    urls = set()
    providers = [scan_alienvault(domain, should_sort), scan_urlscan(domain)]
    if hybrid_analysis_key:
        providers.append(scan_hybrid_analysis(domain, hybrid_analysis_key))
    else:
        print("\033[93mNo API key for Hybrid Analysis\033[0m")

    if virus_total_key:
        providers.append(scan_virus_total(domain, VirusTotalRequester(virus_total_key), should_sort))
    else:
        print("\033[93mNo API key for VirusTotal\033[0m")

    for time, url in merge_results(should_sort, *providers):
        if url not in urls:
            urls.add(url)
            yield time, url


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find secret URLs.')
    parser.add_argument('--domain', help='The domain to search', required=True)
    parser.add_argument('-f', '--filter', help='Only show URLs with secrets', action='store_true')
    parser.add_argument('-s', '--sorted', help='Sort results from newest to oldest', action='store_true')
    parser.add_argument('--hybrid-analysis-key', help='The API key for hybrid analysis')
    parser.add_argument('--virus-total-key', help='The API key for VirusTotal')
    args = parser.parse_args()

    for time, url in scan_all(args.domain, args.sorted, args.hybrid_analysis_key, args.virus_total_key):
        score = calculate_url_score(url)
        line = "%s - %s" % (str(time), url)
        if score >= 100:
            print("\033[91m%s\033[0m" % line)
        elif not args.filter:
            print(line)
