import requests
import json

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def createAlert():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/account/alert/"
    alertId = "1105476115" # Retrieved from iserver/account/{AccountId}/alerts
    params = "type=Q" # Angel didn't say why, but this is required.

    request_url = "".join([base_url, endpoint, alertId, "?", params])

    alert_req = requests.get(url=request_url, verify=False)

    print(alert_req.status_code)
    if alert_req.status_code == 200:
        alert_json = json.dumps(alert_req.json(), indent=2)
        print(alert_json)


if __name__ == "__main__":
    createAlert()