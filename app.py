from scanner.sqli import test_sqli
from scanner.xss import test_xss
from scanner.portscan import scan_ports
from scanner.crawler import extract_links


def run_scan(target, selected_scans):
    crawled_links = extract_links(target)

    sqli_results = []
    xss_results = []
    ports = {}

    if "sqli" in selected_scans or "xss" in selected_scans:
        for link in crawled_links:
            if "?" in link:

                if "sqli" in selected_scans:
                    sqli_vulns = test_sqli(link)
                    if sqli_vulns:
                        sqli_results.extend(sqli_vulns)

                if "xss" in selected_scans:
                    xss_vulns = test_xss(link)
                    if xss_vulns:
                        xss_results.extend(xss_vulns)

    if "port" in selected_scans:
        ports = scan_ports(target)

    return {
        "target": target,
        "total_links": len(crawled_links),
        "sqli_results": sqli_results,
        "xss_results": xss_results,
        "ports": ports
    }