import requests
import json

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def createAlert():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/account/DU5240685/alerts"

    alert_req = requests.get(url=base_url+endpoint, verify=False)

    print(alert_req.status_code)
    if alert_req.status_code == 200:
        alert_json = json.dumps(alert_req.json(), indent=2)
        print(alert_json)


if __name__ == "__main__":
    createAlert()