# VirusTotalAPIWrapper
Wrapper for the Virus Total Public API

Generated Usage Details:

usage: virustotal.py [-h] [-s] [-v] [-j] [-r] [-u] [-U] [-i] HashPathUrl

Search and Scan Hashes, URLs and Files and Download from VirusTotal

positional arguments:
  HashPathUrl      Enter the MD5/SHA1/256 Hash/ Path to File/ URL

optional arguments:
  -h, --help       show this help message and exit<br>
  -s, --search     Search VirusTotal for HashPathUrl<br>
  -v, --verbose    Use the VirusTotal verbose output<br>
  -j, --jsondump   Dumps the full VT report to file<br>
                    (VirusTotalDump<md5/sha1/sha256>.json)<br>
  -r, --rescan     Request Rescan with Current A/V Definitions<br>
  -u, --url        Send URL and request a scan<br>
  -U, --UrlReport  Request URL Report<br>
  -i, --ip         Request an IP address to be scanned by VT<br>
