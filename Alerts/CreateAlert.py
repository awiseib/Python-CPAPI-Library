import requests
import json

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def createAlert():
    base_url = "https://localhost:5000/v1/api/"
    endpoint = "iserver/account/DU5240685/alert"

    json_body = {
        "alertMessage": "THIS IS MY SUCCESSFUL TEST ALERT", 
        "alertName": "AAPL", 
        "alertRepeatable": 1,
        "conditions": [ 
            {
            "conidex": "265598@SMART", 
            "logicBind": "n", 
            "operator": ">=", 
            "triggerMethod": "0", 
            "type": 1, 
            "value": "192.08" 
            }
        ],
        "outsideRth": 1,
        "sendMessage": 1, # Send an Email
        "email": "awise@interactivebrokers.com",
        "iTWSOrdersOnly": 0, # IBKR Mobile Notification 
        "showPopup": 1,  #  Create popup alert
        "tif": "GTC" 
    }

    alert_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)

    print(alert_req.status_code)
    if alert_req.status_code == 200:
        alert_json = json.dumps(alert_req.json(), indent=2)
        print(alert_json)
    else:
        
        alert_json = json.dumps(alert_req.json(), indent=2)
        print(alert_json)


if __name__ == "__main__":
    createAlert()