import json
import requests
import pprint
import ssl
import websocket
import time
import threading
# Ignore insecure error messages
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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



baseUrl = "localhost:5001/v1/api"
accountId = "DU5240685"
conid = 679701407



# -------------------------------------------------------------------
# Request #0: Logout to kill prior sessions
# -------------------------------------------------------------------
def logout():
    
    url = f'https://{baseUrl}/logout'

    # Prepare and send request to /portfolio/accounts, print request and response.
    accounts_request = requests.post(url=url, verify=False)
    print(pretty_request_response(accounts_request))


# -------------------------------------------------------------------
# Request #1: Initiate session with ssodh/init
# -------------------------------------------------------------------
def ssodhInit():
    # Initial, non-computed elements of request to /portfolio/accounts.
    
    url = f'https://{baseUrl}/iserver/auth/ssodh/init'

    json_data = {"compete":True, "publish": True}

    # Prepare and send request to /portfolio/accounts, print request and response.
    accounts_request = requests.post(url=url, json=json_data, verify=False)
    print(pretty_request_response(accounts_request))

# -------------------------------------------------------------------
# Request #2: Using LST to request /tickle and print session value
# -------------------------------------------------------------------
def tickle():
    # Initial, non-computed elements of request to /portfolio/accounts.
    
    url = f'https://{baseUrl}/tickle'

    # Prepare and send request to /portfolio/accounts, print request and response.
    tickle_request = requests.post(url=url, verify=False)
    # tickle_response = session_object.send(tickle_request.prepare())
    print(pretty_request_response(tickle_request))
    global TICKLE_COOKIE
    TICKLE_COOKIE = tickle_request.json()['session']
# -------------------------------------------------------------------
# Request #3: Using LST to request /md loop
# -------------------------------------------------------------------

def mdSnapshot():
    # Initial, non-computed elements of request to /portfolio/accounts.
    
    url = f'https://{baseUrl}/iserver/marketdata/snapshot?conids={conid}&fields=31,84,86'

    # Prepare and send request to /portfolio/accounts, print request and response.
    accounts_request = requests.get(url=url, verify=False)
    print(pretty_request_response(accounts_request))

def confirmReply(jsonContent):
    try:
        if json.loads(jsonContent.content)[0]['id']:
            replyId = json.loads(jsonContent.content)[0]['id']
            url = f'https://{baseUrl}/iserver/reply/{replyId}'

            jsonData={"confirmed":True}

            confirm_request = requests.post(url=url, verify=False, json=jsonData)
            print(pretty_request_response(confirm_request))
            confirmReply(confirm_request)
    except:
        try:
            if json.loads(jsonContent.content)[0]['order_id']:
                global ORDER_ID
                ORDER_ID = json.loads(jsonContent.content)[0]['order_id']
        except:
            print("Reply Error")

def placeOrder():
    time.sleep(3)
    url = f'https://{baseUrl}/iserver/account/{accountId}/orders/whatif'

    jsonData = {
        "orders":[
            {
                "conid": conid,
                "orderType": "MKT",
                "side": "BUY",
                "tif": "DAY", 
                "quantity":107
            }
        ]
    }

    # Prepare and send request to /portfolio/accounts, print request and response.
    post_request = requests.post(url=url, verify=False, json=jsonData)
    print(pretty_request_response(post_request))
    confirmReply(post_request)

def notifCheck(jmsg):
    
    url = f'https://{baseUrl}/iserver/notification'

    for orderNotif in jmsg["args"]:
        if "orderId" in orderNotif:
            orderId = orderNotif["orderId"]
            reqId = orderNotif["reqId"]
            options = orderNotif["options"]
            json_data = {
                "orderId":orderId,
                "reqId":reqId,
                "text": options[0]
            }
            accounts_request = requests.get(url=url, verify=False, json=json_data)
            print(pretty_request_response(accounts_request))
# -------------------------------------------------------------------
# Generic endpoint for testing anything
# -------------------------------------------------------------------

def on_message(ws, message):
    print(message)
    jmsg = json.loads(message.decode('utf-8'))
    if jmsg["topic"] == "ntf":
            threading.Thread(target=notifCheck, args=[jmsg], daemon=True).start()

def on_error(ws, error):
    print(error)

def on_close(ws, r1, r2):
    print("## CLOSED! ##")
    print(f"r1:{r1}")
    print(f"r2:{r2}")

def on_open(ws):
    print("Opened Connection")
    ws.send('{"session":"%s"}' % TICKLE_COOKIE)
    time.sleep(2)
    ws.send('sor+{}')
    placeOrder()


if __name__ == "__main__":
    # logout()
    ssodhInit()
    tickle()
    mdSnapshot()
    time.sleep(1)
    mdSnapshot()
    time.sleep(1)

    ws = websocket.WebSocketApp(
        url=f"wss://{baseUrl}/ws",
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        header=["User-Agent: python/3.11"],
        # cookie=f"api={session_cookie}"
    )
    ws.run_forever(sslopt={"cert_reqs":ssl.CERT_NONE})