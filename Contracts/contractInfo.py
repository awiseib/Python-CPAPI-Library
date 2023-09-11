import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# reauthenticate
def contractInfo():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/secdef/info"

    conid="conid=265598"
    # secType = "secType=STK"
    # month = "month=JUL23"
    # exchange = "exchange=CME"
    # strike = "strike=4800"
    # right = "right=C"

    # params = "&".join([conid, secType, month, exchange, strike, right])
    params = "&".join([conid])
    request_url = "".join([base_url, endpoint, "?", params])

    contract_req = requests.get(url=request_url, verify=False)
    contract_json = json.dumps(contract_req.json(), indent=2)

    print(contract_req)
    print(contract_json)

if __name__ == "__main__":
    contractInfo()