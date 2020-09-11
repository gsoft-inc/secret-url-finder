from providers.alienvault_otx_provider import AlienVaultOTXProvider
from providers.common_crawl_provider import CommonCrawlProvider
from providers.hybrid_analysis_provider import HybridAnalysisProvider
from providers.urlscan_provider import UrlScanProvider
from providers.virustotal_provider import VirusTotalProvider
from providers.wayback_machine_provider import WaybackMachineProvider


def create_providers(filtered_extensions, should_sort, urlscan_key, hybrid_analysis_key, virus_total_key):
    yield UrlScanProvider(urlscan_key, filtered_extensions)
    yield CommonCrawlProvider(filtered_extensions)
    yield WaybackMachineProvider(filtered_extensions, should_sort)
    yield AlienVaultOTXProvider(filtered_extensions, should_sort)

    if hybrid_analysis_key:
        yield HybridAnalysisProvider(filtered_extensions, should_sort, hybrid_analysis_key)
    else:
        print("\033[93mNo API key for Hybrid Analysis\033[0m")

    if virus_total_key:
        yield VirusTotalProvider(filtered_extensions, should_sort, virus_total_key)
    else:
        print("\033[93mNo API key for VirusTotal\033[0m")
