# Library Imports
import requests
import time
import urllib3
import json

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def reqScannerParamsHmds():
    params_url = "https://localhost:5000/v1/api/hmds/scanner/params"
    params_req = requests.get(url=params_url, verify=False)
    open('../Python CPAPI Library/hmdsScannerParams.xml', 'wb').write(params_req.content)
    # You can import os then run "os.getcwd()" to see pythons default dir. 
    return params_req

# The HMDS scanner is marked as beta in our Documentation
# I find this is best used for Bonds as it is the most emergent structure. 
# It is also the most similar to the TWS API Scanner Structure.
def reqHmdsScannerBond():
    scan_url = "https://localhost:5000/v1/api/hmds/scanner"
    scan_body = {
        "instrument": "BOND",
        "locations": "BOND.US",
        "scanCode": "HIGH_BOND_ASK_YIELD_ALL",
        "secType": "BOND",
        "filters": [{
            "maturityDateAbove": "20230431",
            "maturityDateBelow": "",
            "industryLike": "",
            "bondAskYieldAbove": "",
            "bondAskYieldBelow": 15.819,
            "couponRateAbove": "",
            "couponRateBelow": "",
            "moodyRatingAbove": "",
            "moodyRatingBelow": "",
            "spRatingAbove": "",
            "spRatingBelow": "",
            "currencyLike": "USD",
            "issuerCountryIs": "US",
            "bondIssuerLike":"MOODY"
        }]
    }
    scan_req = requests.post(url=scan_url, verify=False, json=scan_body)
    # print(scan_req)
    # print(scan_req.text)
    results = json.loads(scan_req.text)["Contracts"]["Contract"]
    for i in results:
        print(i)
        
def reqHmdsScannerStk():
    scan_url = "https://localhost:5000/v1/api/hmds/scanner"
    scan_body = {
        "instrument": "ETF.EQ.US",
        "scanCode": "MOST_ACTIVE_USD",
        "locations": "ETF.EQ.US.MAJOR",
        "secType": "STK",
        "size":30,
        "filters": []
    }
    scan_req = requests.post(url=scan_url, verify=False, json=scan_body)
    results = json.loads(scan_req.text)["Contracts"]["Contract"]
    for i in results:
        print(i)     
    
    # print(len(results))

def reqHmdsScannerFund():
    scan_url = "https://localhost:5000/v1/api/hmds/scanner"
    scan_body = {
        "instrument": "FUND",
        "locations": "FUND.US",
        "scanCode": "SCAN_mfTotalReturnScoreOverall_DESC",
        "secType": "FUND",
        "filters": [{
            "maturityDateAbove": "20230431",
            "maturityDateBelow": "",
            "industryLike": "",
            "bondAskYieldAbove": "",
            "bondAskYieldBelow": "",
            "couponRateAbove": "",
            "couponRateBelow": "",
            "moodyRatingAbove": "",
            "moodyRatingBelow": "",
            "spRatingAbove": "",
            "spRatingBelow": "",
            "currencyLike": "USD",
            "issuerCountryIs": "US",
            "bondIssuerLike":""
        }]
    }
    scan_req = requests.post(url=scan_url, verify=False, json=scan_body)
    results = json.loads(scan_req.text)["Contracts"]["Contract"]
    for i in results:
        print(i)

def reqHmdsScannerCombo():
    scan_url = "https://localhost:5000/v1/api/hmds/scanner"
    scan_body = {
        "instrument": "NATCOMB",
        "scanCode": "UNDCONID",
        "locations": "NATCOMB.OPT.US",
        "secType": "BAG",
        "size":100,
        "filters": []
    }
    scan_req = requests.post(url=scan_url, verify=False, json=scan_body)
    results = json.loads(scan_req.text)["Contracts"]["Contract"]
    for i in results:
        print(i)     
    
    # print(len(results))

def reqIserverScanner():
    scan_url = "https://localhost:5000/v1/api/iserver/scanner/run"
    scan_body = {
        "instrument": "ETF.EQ.US",
        "type": "MOST_ACTIVE_USD",
        "locations": "ETF.EQ.US.MAJOR",
        "filter":[]
    }
    scan_req = requests.post(url=scan_url, verify=False, json=scan_body)
    
    print(scan_req)
    print(scan_req.text)
    # results = json.loads(scan_req.text)["contracts"]
    # for i in results:
    #     print(i)

def main():
    # reqScannerParamsIserver()
    # reqScannerParamsHmds()
    # reqHmdsScannerBond()
    # reqHmdsScannerStk()
    # reqHmdsScannerFund()
    reqHmdsScannerCombo()
    # reqIserverScanner()
    
if __name__ == "__main__":
    main()