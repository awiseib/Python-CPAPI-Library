# Library Imports
import requests
import time
import urllib3
import json

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def reqScannerParamsHmds():
    params_url = "https://localhost:5000/v1/api/iserver/scanner/params"
    params_req = requests.get(url=params_url, verify=False)
    content = json.loads(params_req.text)

    contentFile = open('../Python CPAPI Library/iserverScannerParams.xml', 'w')
    
    for section in content.keys():
        contentFile.write(section)
        contentFile.write("\n")

        for tag in content[section]:
            contentFile.write(str(tag))
            contentFile.write("\n")
        contentFile.write("\n")

    contentFile.close()

if __name__ == "__main__":
    reqScannerParamsHmds()