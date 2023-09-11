import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def historicalData(conidVal):
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/marketdata/history"

    conid=f"conid={conidVal}"
    period="period=1w"
    bar="bar=1d"
    startTime="startTime=20230824-16:00:00"
    outsideRth="outsideRth=true"
    barType="barType=AllLast"

    params = "&".join([conid, period, bar, startTime, outsideRth, barType])
    request_url = "".join([base_url, endpoint, "?", params])

    hd_req = requests.get(url=request_url, verify=False)
    if hd_req.status_code == 500:
        print(hd_req.status_code)
        print(hd_req.text)
    else:
        hd_json = json.dumps(hd_req.json(), indent=2)
        print(hd_json)

if __name__ == "__main__":
    historicalData(265598)