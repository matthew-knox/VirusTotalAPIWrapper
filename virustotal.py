#!/usr/bin/python

'''
  Wrapper for the Virus Total Public API
  Implements the following functionality:
    Requesting a File to be scanned by VT
    Requesting a File Report from a pre-existing file in VT database
    Requesting a File to be rescanned by VT
    Requesting a URL be scanned by VT
    Requesting a URL Report for a previously scanned URL in VT database

  Future functionality:
    Improved error handling
    Improved consistency in json report printing
    Improved option parsing and passing
      [Really ugly right now]
'''


import json, urllib, urllib2, argparse, hashlib, re, sys
'''
  import needed for multipart post data in scanFile()
  see VirusTotal Public API Documentation for more details
'''
import postfile

'''
  Personal API KEY
  Used as default
'''
MY_API_KEY = "47e020b210edc530d83696e912577cd63223c4a6e5a436ca928ed5c7d12e1bd5"
'''
  API KEY Properties
  Privileges:     PUBLIC
  Request Rate:   4       requests/minute
  Daily Quota:    5760    requests/day
  Monthly Quota:  178560  requests/month
  Status:         ENABLED
'''

class vtAPI():
    def __init__(self, key=MY_API_KEY):
      self.api = key
      self.base = 'https://www.virustotal.com/vtapi/v2/'

    def scanFile(self, file):
      '''
        Sends the given parameter file to VT for scanning
        Files sent for scanning have lowest priority,
        could take up to several hours to be scanned
        POST to https://www.virustotal.com/vtapi/v2/file/scan
      '''
      fields = [("apikey", self.api)]
      file_to_send = open(file, "rb").read()
      files = [("file", file, file_to_send)]
      url = self.base + "file/scan"
      json = postfile.post_multipart(self.base[:-10], url, fields, files)
      if json['response_code'] == 1:
        print "\n\tVirus Total File Scan Requested for --" + json['md5']
      else:
        print "\n\tScan Request Failed"

    def queryRescan(self,md5):
      '''
        Requests a file rescan of file designated by
        the parameter md5
        POST to https://www.virustotal.com/vtapi/v2/file/rescan
      '''
      params = {
                'resource':md5,
                'apikey':self.api
                }
      url = self.base + "file/rescan"
      data = urllib.urlencode(params)
      result = urllib2.urlopen(url,data)
      print "\n\tVirus Total Rescan Initiated for -- " + md5 + " (Requery in 10 Mins)"
    
    def getReport(self,md5):
      '''
        Get the most recent report for the file designated
        by the parameter md5
        POST to https://www.virustotal.com/vtapi/v2/file/report
      '''
      params = {
                'resource':md5,
                'apikey':self.api
                }
      url = self.base + "file/report"
      data = urllib.urlencode(params)
      result = urllib2.urlopen(url,data)
      jdata =  json.loads(result.read())
      return jdata

    def urlScan(self, url):
      '''
        Submits the URL designated by the parameter url
        to be scanned by VT
        POST to https://www.virustotal.com/vtapi/v2/url/scan
      '''
      params = {
                'url':url,
                'apikey':self.api
                }
      url = self.base + "url/scan"
      data = urllib.urlencode(params)
      result = urllib2.urlopen(url,data)
      jsond = json.loads(result.read())
      print "\n\tVirus Total URL Scan Initiated--"
      if jsond['response_code'] == 1:
        print "\n\t", jsond['scan_date'],":\n\t\t" + jsond['verbose_msg']
        print "\t\t>>>If you wanted a report on the url, use the -U flag"

    def getURLReport(self, url):
      '''
        Request report data about the URL designated
        by the parameter url
        POST to https://www.virustotal.com/vtapi/v2/url/report
        [Print is still a little off as far as verbose printing goes]
      '''
      params = {
                'resource':url,
                'apikey':self.api
                }
      url = self.base + "url/report"
      data = urllib.urlencode(params)
      response = urllib2.urlopen(url, data)
      jsond = json.loads(response.read())
      if jsond["response_code"] == 1:
        print "\n\tVirus Total URL Scan report\n", parseUrlResponse(jsond)

# Md5 Functions

def checkMD5(checkval):
  if re.match(r"([a-fA-F\d]{32})", checkval) == None:
    md5 = md5sum(checkval)
    return md5.upper()
  else: 
    return checkval.upper()

def md5sum(filename):
  fh = open(filename, 'rb')
  m = hashlib.md5()
  while True:
      data = fh.read(8192)
      if not data:
          break
      m.update(data)
  return m.hexdigest() 

def parseUrlResponse(resp):
  '''
    Parsing function for better printing of resulting json data

  '''
  print "\n\tResults for URL: ",resp['url']
  print "\n\tDetected by: ",resp['positives'],'/',resp['total'],'\n'
  for x in resp['scans']:
    print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 14 else '','\t',resp['scans'][x]['detected'], '\t',resp['scans'][x]['result']

def parse(it, md5, verbose, jsondump):
  '''
    Parsing function for better printing of result json (it)
    parameter md5 contains the hash value of the requested file
    parameters verbose and jsondump set according to CLI flags
  '''
  if it['response_code'] == 0:
    print md5 + " -- Not Found on Virus Total"
    return 0

  print "\n\tResults for MD5: ",it['md5'],"\n\n\tDetected by: ",it['positives'],'/',it['total'],'\n'
  if 'Sophos' in it['scans']:
    print '\tSophos Detection:',it['scans']['Sophos']['result'],'\n'
  if 'Kaspersky' in it['scans']:
    print '\tKaspersky Detection:',it['scans']['Kaspersky']['result'], '\n'
  if 'ESET-NOD32' in it['scans']:
    print '\tESET Detection:',it['scans']['ESET-NOD32']['result'],'\n'
  if 'Avira' in it['scans']:
    print '\tAvira Detection:',it['scans']['Avira']['result'],'\n'

  print '\tScanned on:',it['scan_date']
  
  if jsondump == True:
    dumpfile = open("VirusTotalDump" + md5 + ".json", "w")
    pprint(it, dumpfile)
    dumpfile.close()
    print "\n\tJSON Written to File -- " + "VTDL" + md5 + ".json"

  if verbose == True:
    print '\n\tVerbose Flag Detected. VT Verbose Output:\n'
    for x in it['scans']:
     print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 14 else '','\t',it['scans'][x]['detected'], '\t',it['scans'][x]['result']

def main():

  opt=argparse.ArgumentParser(description="Search and Scan Hashes, URLs and Files from VirusTotal")
  opt.add_argument("HashPathUrl", help="Enter the MD5/SHA1/256 Hash/ Path to File/ URL")
  opt.add_argument("-s", "--search", action="store_true", help="Search VirusTotal for HashPathUrl")
  opt.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Use the VirusTotal verbose output")
  opt.add_argument("-j", "--jsondump", action="store_true", dest="jsondump", help="Dumps the full VT report to file (VirusTotalDump<md5/sha1/sha256>.json)")
  opt.add_argument("-r", "--rescan",action="store_true", help="Request Rescan with Current A/V Definitions")
  opt.add_argument("-u", "--url", action="store_true", help="Send URL and request a scan")
  opt.add_argument("-U", "--UrlReport", action="store_true", dest="UrlReport", help="Request URL Report")
  opt.add_argument("-i", "--ip", action="store_true", help="Request an IP address to be scanned by VT")

  if len(sys.argv)<=2:
    opt.print_help()
    sys.exit(1)
  options= opt.parse_args()

  vt=vtAPI()

  if not options.url and not options.UrlReport:
    md5 = checkMD5(options.HashPathUrl)

  if options.UrlReport:
    vt.getURLReport(options.HashPathUrl)

  if options.search or options.jsondump or options.verbose:
    parse(vt.getReport(md5), md5 ,options.verbose, options.jsondump)

  if options.rescan:
    vt.rescan(md5)

  if options.url:
    vt.urlScan(options.HashPathUrl)

if __name__ == '__main__':
    main()
