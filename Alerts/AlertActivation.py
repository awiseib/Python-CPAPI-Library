import requests
import json

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def activateAlert():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/account/DU5240685/alert/activate"

    json_body = {
        "alertId":1105476114,
        "alertActive":0 # 1 to activate, 0 to deactivate
    }

    alert_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)

    print(alert_req.status_code)
    if alert_req.status_code == 200:
        alert_json = json.dumps(alert_req.json(), indent=2)
        print(alert_json)


if __name__ == "__main__":
    activateAlert()