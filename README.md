# secret-url-finder
Tool that finds URLs for a given domain by using different sources:
* [urlscan.io](https://urlscan.io/)
* [Alienvault OTX](https://otx.alienvault.com)
* [Wayback Machine](https://archive.org/web/)
* [Common Crawl](https://commoncrawl.org/)
* [Hybrid Analysis](https://www.hybrid-analysis.com) - Requires an API key.
* [VirusTotal](https://www.virustotal.com) - Requires an API key.

URLs that could contain secret values are highlighted in red.

## Usage

```
secret-url-finder.py [-h] --domain DOMAIN [-f] [-s] [-u] [--hybrid-analysis-key HYBRID_ANALYSIS_KEY] [--virus-total-key VIRUS_TOTAL_KEY] [--ignored-extensions IGNORED_EXTENSIONS]

required arguments:
  --domain DOMAIN       The domain to search
  
optional arguments:
  -h, --help            show this help message and exit
  -f, --filter          Only show URLs with secrets
  -s, --sorted          Sort results from newest to oldest
  -u, --url-only        Only displays the URLs
  --urlscan-key         URLSCAN_KEY
                        The API key for urlscan. Not mandatory, but helps with rate limiting
  --hybrid-analysis-key HYBRID_ANALYSIS_KEY
                        The API key for hybrid analysis
  --virus-total-key VIRUS_TOTAL_KEY
                        The API key for VirusTotal
  --ignored-extensions IGNORED_EXTENSIONS
                        File extensions to ignore. Defaults to: "gif,jpg,png,css,svg,woff,woff2"
```