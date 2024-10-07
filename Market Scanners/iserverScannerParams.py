import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scanParams():
    base_url = "https://localhost:5001/v1/api/"
    endpoint = "iserver/scanner/params"

    params_req = requests.get(url=base_url+endpoint, verify=False)
    params_json = json.dumps(params_req.json(), indent=2)

    paramFiles = open("./iserverScannerParams.xml", "w")
    
    for i in params_json:
        paramFiles.write(i)

    paramFiles.close()

    print(params_req.status_code)

if __name__ == "__main__":
    scanParams()