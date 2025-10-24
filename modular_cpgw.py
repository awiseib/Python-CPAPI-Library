"""
Slightly more complex implementation though provides easier request 
structure and an authentication check to avoid duplicate authentication.

Requires Python packages: pycryptodome, requests

Enter configuration values in Prequisites section below before running.
"""

from datetime import datetime,timedelta
import json
import pprint
import requests
import requests.adapters
from ssl import CERT_NONE
from time import sleep
import urllib3
from websocket import WebSocketApp

# Ignore insecure error messages
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


if requests.get(url="https://localhost:5001",verify=False).status_code ==200:
    baseUrl = "localhost:5001/v1/api"
elif requests.get(url="https://localhost:5000",verify=False).status_code ==200:
    baseUrl = "localhost:5000/v1/api"
else:
    print("Please be sure to launch your Client Portal Gateway.")
    print("If you are connecting to a host other than localhost:5001 or localhost:5000, please modify the code.")
    exit(1)

print(f"Base URL set to {baseUrl}")

def standard_request(method: str, endpoint: str, query_params={}, content={}, print_data=True):
    # Initial, non-computed elements of request to /portfolio/accounts.
    url = f'https://{baseUrl}{endpoint}'
    headers = {}

    # Add User-Agent header, required for all requests. Can have any value.
    headers["User-Agent"] = "python/3.11"
    headers["Accept"] = "*/*"
    headers["Connection"] = "keep-alive"

    s = requests.Session()
    retries = requests.adapters.Retry(
        total=3,
        backoff_factor=0.5
        )
    s.mount("https://", requests.adapters.HTTPAdapter(max_retries=retries))

    try:
        with s.request(method=method, url=url, headers=headers, params=query_params, json=content, verify=False) as req:
            if print_data == True:
                print(pretty_request_response(req))
            else:
                sleep(1)
            if req.status_code == 200:
                return req
            else:
                print("## REQUEST FAILED ##")
                print(f"Failed with status code {req.status_code}")
                print(req.connection)
    except Exception as e:
        print(f"Failed to submit request. Received error: {e}")

def on_message(ws, message):
    jmsg = json.loads(message.decode('utf-8'))
    print(f"{datetime.now() } {jmsg}")
    if jmsg["topic"] == 'sts':
        ws_msg = 'sor+{"filters": ["cancelled"]}' 
        ws.send()

def on_error(ws, error):
    print(f"Error received: {error}")

def on_close(ws, r1, r2):
    print("## CLOSED! ##")
    print(f"r1:{r1}")
    print(f"r2:{r2}")

def on_open(ws):
    print("Opened Connection")
    
def write_json_to_file(response: requests.Response, fileName: str):
    json_content = response.json()
    with open(rf"C:\Users\awise\Code\Python CPAPI Library\Files\{fileName}", 'w') as f:
        json.dump(json_content, f,indent=4)

def auth_check():
    print("Running authentication procedure..")
    if standard_request(method="GET", endpoint="/iserver/auth/status", print_data=False).status_code == 401:
        print(f"Your session is not authenticated.")
        print(f"Log in to https://{baseUrl[14:]} ")
        exit(1)
    
    init_details = standard_request(
        method="POST", 
        endpoint="/iserver/auth/ssodh/init",
        content={"compete": True, "publish": True},
        print_data=False
    )
    
    if not init_details.status_code and init_details.status_code != 200:
        print(f"Failed to authenticate due to code {init_details.status_code}")
        print(init_details.content)
        exit(1)
    
    while standard_request(
                method="GET", 
                endpoint="/iserver/accounts",
                print_data=False
            ).text == '':
        
        sleep(0.25)
    try:
        iserver_accounts = standard_request(
            method="GET", 
            endpoint="/iserver/accounts",
            print_data=False
        )
        accountId = iserver_accounts.json()["selectedAccount"]
    except requests.exceptions.JSONDecodeError as e:
        print(e)
        exit()
        
    return accountId

if __name__ == "__main__":
    accountId = auth_check()    
    
    # Ignores order precautions to expedite order submission flow. 
    standard_request(
        method="POST", 
        endpoint="/iserver/questions/suppress", 
        content={"messageIds":["o383","o10164","o10223","o403","o10331","o2137","o10082","o10332", "o163","o10333","o10334","o2136","o10335","o10151","o10288","o10152","o10153","o2165","p12","o354","o383","o451","o10138","o163","o382", "o354"]}
    )

    standard_request(
        method="POST", 
        endpoint=f"/iserver/account/{accountId}/orders" if "DU" in accountId else f"/iserver/account/{accountId}/orders/whatif", 
        content={"orders":[
            {
            "price": 253.50,
            "quantity": 100,
            "side": "Buy",
            "orderType": "LMT",
            "tif": "DAY",
            # "outsideRTH": True,
            "conid": 265598
            
            }
        ]}
    )

    # Get the session token to init the websocket.
    session_token = standard_request(
        method="POST", 
        endpoint="/tickle",
        print_data=False
        ).json()["session"]

    # Initiate our Websocket, passing our Access token as a query param
    # Be sure to pass the session token from /tickle as a cookie header for the session.
    ws = WebSocketApp(
        url=f"wss://{baseUrl}/ws",
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        # header=["User-Agent: python/3.11"],
        cookie=f"api={session_token}"
    )
    
    ws.run_forever(sslopt={"cert_reqs":CERT_NONE})
