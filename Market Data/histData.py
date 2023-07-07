import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def historicalData():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "hmds/history"

    conid="conid=265598"
    period="period=1w"
    bar="bar=1d"
    outsideRth="outsideRth=true"
    barType="barType=midpoint"

    params = "&".join([conid, period, bar,outsideRth, barType])
    request_url = "".join([base_url, endpoint, "?", params])

    hd_req = requests.get(url=request_url, verify=False)
    hd_json = json.dumps(hd_req.json(), indent=2)

    print(hd_req)
    print(hd_json)

if __name__ == "__main__":
    historicalData()