import requests
import json

# Disable SSL Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def historicalData(conidVal):
    base_url = "https://localhost:5000/v1/api/"
    endpoint = f"iserver/marketdata/{conidVal}/unsubscribe"

    request_url = "".join([base_url, endpoint])
    print(request_url)

    hd_req = requests.get(url=request_url, verify=False)
    if hd_req.status_code != 200:
        print(hd_req.status_code)
        print(hd_req.text)
    else:
        hd_json = json.dumps(hd_req.json(), indent=2)
        print(hd_json)

if __name__ == "__main__":
    for i in ["265598", "8314", "8894", "4815747", "76792991", "14094"]: # AAPL, IBM, KO, NVDA, TSLA, BMW
    
        historicalData(i)