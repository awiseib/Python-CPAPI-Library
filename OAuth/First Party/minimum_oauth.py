import json
import requests
import pprint
import websocket
import time
from threading import Thread

# List of response headers to print (all others discarded)
RESP_HEADERS_TO_PRINT = ["Content-Type", "Content-Length", "Date", "Set-Cookie", "User-Agent"]

def pretty_request_response(resp: requests.Response) -> str:
    """Print request and response legibly."""
    req = resp.request
    rqh = '\n'.join(f"{k}: {v}" for k, v in req.headers.items())
    rqh = rqh.replace(', ', ',\n    ')
    rqb = f"\n{pprint.pformat(json.loads(req.body))}\n" if req.body else ""
    try:
        rsb = f"\n{pprint.pformat(resp.json())}\n" if resp.text else ""
    except json.JSONDecodeError:
        rsb = resp.text
    rsh = '\n'.join([f"{k}: {v}" for k, v in resp.headers.items() if k in RESP_HEADERS_TO_PRINT])
    return_str = '\n'.join([
        80*'-',
        '-----------REQUEST-----------',
        f"{req.method} {req.url}",
        rqh,
        f"{rqb}",
        '-----------RESPONSE-----------',
        f"{resp.status_code} {resp.reason}",
        rsh,
        f"{rsb}\n",
    ])
    return return_str


# Enter your access token here. As long as you have logged in to TradingView in the last 24 hours, you are OK to proceed.
access_token = "c3091a1f99feab85cbca" # rrapi
accountId = "DU74649"

# access_token = "394f3e394b0761a44f8d" # Damian (PAPER)
# access_token = "34816e3a9253e543461b" # Damian (LIVE)

# access_token = "394f3e394b0761a44f8d" # Matt
# accountId = "DU4355398"

realm = "limited_poa"

## Set the base url for all subsequent requests
baseUrl = "api.ibkr.com/v1/api" # LIVE
# baseUrl = "api.ibkr.com/v1/tv" # tradingview


def getReq(uri):
    url = f'https://{baseUrl}{uri}'

    # Set the access token as the header
    oauth_header = 'OAuth oauth_token="%s"' % access_token
    headers = {"Authorization": oauth_header}

    # Add User-Agent header, required for all requests. Can have any value.
    headers["User-Agent"] = "python/3.11"
    
    # Prepare and send request to /portfolio/accounts, print request and response.
    get_request = requests.get(url=url, headers=headers)
    return get_request

def postReq(uri, jsonData):
    url = f'https://{baseUrl}{uri}'

    # Set the access token as the header
    oauth_header = 'OAuth oauth_token="%s"' % access_token
    headers = {"Authorization": oauth_header}

    # Add User-Agent header, required for all requests. Can have any value.
    headers["User-Agent"] = "python/3.11"

    # Prepare and send request to /portfolio/accounts, print request and response.
    post_request = requests.post(url=url, headers=headers, json=jsonData)
    return post_request

# -------------------------------------------------------------------
# Request #3(?): Reply to the replyId to pass the order through.
# -------------------------------------------------------------------
def confirmReply(jsonContent):
    try:
        if json.loads(jsonContent.content)[0]['id']:
            replyId = json.loads(jsonContent.content)[0]['id']
            method = 'POST'
            url = f'https://{baseUrl}/iserver/reply/{replyId}'

            # Set the access token as the header
            oauth_header = 'OAuth oauth_token="%s"' % access_token
            headers = {"Authorization": oauth_header}

            # Add User-Agent header, required for all requests. Can have any value.
            headers["User-Agent"] = "python/3.11"

            jsonData={"confirmed":True}

            confirm_request = requests.post(url=url, headers=headers, json=jsonData)
            print(confirm_request.status_code)
            print(confirm_request.json())
            confirmReply(confirm_request)
    except:
        print()

def fraqOrder(uri):
    url = f'https://{baseUrl}{uri}'

    # Set the access token as the header
    oauth_header = 'OAuth oauth_token="%s"' % access_token
    headers = {"Authorization": oauth_header}

    # Add User-Agent header, required for all requests. Can have any value.
    headers["User-Agent"] = "python/3.11"

    jsonData={"orders": [{"conid":8314,"orderType": "LMT","price": 189,"side": "BUY","tif": "DAY","cashQty": 50.25}]}

    # Prepare and send request to /portfolio/accounts, print request and response.
    post_request = requests.post(url=url, headers=headers, json=jsonData)
    print(post_request.json())
    confirmReply(post_request)
    return post_request

def on_message(ws, message):
    print(message.decode("utf-8"))

def on_error(ws, error):
    print(error)

def on_close(ws, r1, r2):
    print("## CLOSED! ##")
    print(f"r1:{r1}")
    print(f"r2:{r2}")

def on_open(ws):
    print("Opened Connection")
    tickle = getReq("/tickle") # Get the session token from /tickle
    sessionToken= tickle.json()['session']
    ws.send('{"session":"%s"}' % sessionToken)

if __name__ == "__main__":

    # ws = websocket.WebSocketApp(
    #     url=f"wss://{baseUrl}/ws?oauth_token={access_token}",
    #     on_open=on_open, 
    #     # on_open=lambda ws: on_open(ws, sessionToken), # This can be used to send variables, like sessionToken, into websockets.
    #     on_message=on_message,
    #     on_error=on_error,
    #     on_close=on_close,
    #     header=["User-Agent: python/3.11"]
    # )
    # Thread(target=ws.run_forever).start()
    # time.sleep(2)
    # ws.send('sld+%s+{}' % accountId)

    # fraqOrder("/iserver/account/DU5240685/orders").json()
    # print(getReq("/portfolio/DU5240685/positions/265598").json())
    # time.sleep(1)
    print("Start: ", time.localtime())
    
    jsonData={}
    print("Authenticated: ", postReq("/iserver/auth/ssodh/init?publish=true&compete=true", jsonData).json()["authenticated"])

    # print(getReq("/portfolio/subaccounts").json())
    
    # jsonData={"orders": [{"conid":265598,"orderType": "LMT","price": 183,"side": "BUY","tif": "DAY","quantity": 5}]}
    # orderReq = postReq(f"/iserver/account/{accountId}/orders", jsonData).json()
    # print(orderReq)
    order_id = "1551860066" #orderReq[0]['order_id']
    statusReq = getReq(f"/iserver/account/order/status/{order_id}")
    print(statusReq.status_code)
    try:
        print(statusReq.json())
    except:
        print("ERROR!")