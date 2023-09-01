# Library Imports
import requests
import urllib3
import json

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def reqIserverScanner():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "hmds/scanner/run"

    scan_body = {
        "instrument":"STK",
        "locations": "STK.US.MAJOR",
        "scanCode": "TOP_PERC_GAIN",
        "secType": "STK",
        "delayedLocations": "NYSE",
        "maxItems":25,
        "filters":[{
            # "maturityDateAbove": "20230131",
            # "maturityDateBelow": "",
            # "industryLike": "",
            # "bondAskYieldAbove": "",
            # "bondAskYieldBelow": 15.819,
            # "couponRateAbove": "",
            # "couponRateBelow": "",
            # "moodyRatingAbove": "",
            # "moodyRatingBelow": "",
            # "spRatingAbove": "",
            # "spRatingBelow": "",
            # "currencyLike": "USD",
            # "issuerCountryIs": "US",
            # "bondIssuerLike":"MOODY"
        }]
    }

    scan_req = requests.post(url=base_url+endpoint, verify=False, json=scan_body)
    scan_json = json.dumps(scan_req.json(), indent=2)

    print(scan_req.status_code)
    print(scan_json)
    
if __name__ == "__main__":
    reqIserverScanner()
