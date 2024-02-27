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

    # json_body =   {
    #     "orders":[
    #         {
    #             "conid": 479624278, # BTC
    #             "listingExchange":"PAXOS",
    #             # "cOID": f"test_{coid_iter}",
    #             "orderType": "STP",
    #             "price": 43925,
    #             "quantity": 0.0123,
    #             "side": "SELL",
    #             "tif": "Minutes",
    #             # "outsideRTH":True
    #         }
    #     ]
    # }
    json_body = {'orders': [{'acctId': f'{ACCT_ID}', 'conid': 265598, 'conidex': '265598@SMART', 'secType': '265598@STK', 'cOID': 'AAPL-BUY-100', 'parentId': None, 'orderType': 'TRAILLMT', 'listingExchange': 'NASDAQ', 'isSingleGroup': False, 'outsideRTH': True, 'price': 185.5, 'auxPrice': 183, 'side': 'BUY', 'ticker': 'AAPL', 'tif': 'GTC', 'trailingAmt': 1.0, 'trailingType': 'amt', 'referrer': 'QuickTrade', 'quantity': 100, 'useAdaptive': False, 'isCcyConv': False, 'strategy': 'Vwap', 'strategyParameters': {'MaxPctVol': '0.1', 'StartTime': '14:00:00 EST', 'EndTime': '15:00:00 EST', 'AllowPastEndTime': True}}]}
    
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