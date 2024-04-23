import requests
import json
import urllib3
import time

# Ignore insecure error messages
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ACCT_ID = "DU5240685"

def confirmReply(replyId):
    print("Begin confirmReply")

    url = f'https://localhost:5001/v1/api/iserver/reply/{replyId}'

    jsonData={"confirmed":True}

    confirm_request = requests.post(url=url, json=jsonData, verify=False)
    if confirm_request.status_code == 200:
        try:
            if confirm_request.json()[0]["id"]:
                confirmReply(confirm_request.json()[0]["id"])
            else:
                print(confirm_request.status_code)
                print(confirm_request.json())
        except:
            print(confirm_request.status_code)
    else:
        print(confirm_request.status_code)
        print(confirm_request.json())

def orderRequest():
    coid_iter = f"{int(time.time())}"
    base_url = "https://localhost:5001/v1/api/"
    endpoint = f"iserver/account/{ACCT_ID}/orders"

    json_body =   {
        "orders":[
            {
                "conid": 265598,
                "orderType": "LMT",
                "price": 170,
                "quantity": 1,
                "side": "BUY",
                "tif": "DAY",
                # "outsideRTH":True
            }
        ]
    }
    
    order_req = requests.post(url=base_url+endpoint, verify=False, json=json_body)
    order_json = json.dumps(order_req.json(), indent=2)

    print(order_req.status_code)
    print(order_json)
    try:
        if order_req.json()[0]["id"]:
            confirmReply(order_req.json()[0]["id"])
    except:
        pass



if __name__ == "__main__":
    orderRequest()