import requests
import json

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def deleteAlert():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/account/DU5240685/alert/"
    alertId = "1105476115" # Can use '0' to delete all alerts

    request_url = "".join([base_url, endpoint, alertId])

    alert_req = requests.delete(url=request_url, verify=False)

    print(alert_req.status_code)
    if alert_req.status_code == 200:
        alert_json = json.dumps(alert_req.json(), indent=2)
        print(alert_json)


if __name__ == "__main__":
    deleteAlert()