# General Python Imports
import json
import pprint
from datetime import datetime
import websocket
import time

# Python to Excel Imports
import xlwings as xw
from threading import Thread
from queue import Queue

# WEBAPI request imports
import requests
import random
import base64
from urllib.parse import quote, quote_plus
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signature
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Hash import SHA256, HMAC, SHA1


RESP_HEADERS_TO_PRINT = ["Content-Type", "Content-Length", "Date", "Set-Cookie", "User-Agent"]
BASE_URL = "api.ibkr.com/v1/api" 
ACCESS_TOKEN = None
TICKLE_COOKIE = None
BN = 'WebAPI_MD_Lines.xlsx'
LD = 'Sheet1'
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

def oauth():
    credentials = json.load(open(file=r"D:\Code\Python CPAPI Library\credentials.json", mode="r"))
    current_user = credentials['user2']

    with open(current_user['encryption'], "r") as f:
        encryption_key = RSA.importKey(f.read())

    with open(current_user['signature'], "r") as f:
        signature_key = RSA.importKey(f.read())

    with open(current_user['dhparam'], "r") as f:
        dh_param = RSA.importKey(f.read())
        dh_prime = dh_param.n
        dh_generator = dh_param.e  
    global ACCESS_TOKEN
    ACCESS_TOKEN = current_user['access_token']
    access_token = ACCESS_TOKEN
    access_token_secret = current_user['access_token_secret']
    consumer_key = current_user['consumer_key']
    realm = "limited_poa"

    session_object = requests.Session()
    live_session_token = None
    lst_expiration = None
    session_cookie = None

    # Calculate Base String
    dh_random = random.getrandbits(256)
    dh_challenge = hex(pow(base=dh_generator, exp=dh_random, mod=dh_prime))[2:]
    bytes_decrypted_secret = PKCS1_v1_5_Cipher.new(
        key=encryption_key
        ).decrypt(
            ciphertext=base64.b64decode(access_token_secret), 
            sentinel=None,
            )
    prepend = bytes_decrypted_secret.hex()
    base_string = prepend

    # Request Live Session Token
    method = 'POST'
    url = f'https://{BASE_URL}/oauth/live_session_token'
    oauth_params = {
        "oauth_consumer_key": consumer_key,
        "oauth_nonce": hex(random.getrandbits(128))[2:],
        "oauth_timestamp": str(int(datetime.now().timestamp())),
        "oauth_token": access_token,
        "oauth_signature_method": "RSA-SHA256",
        "diffie_hellman_challenge": dh_challenge,
        "oauth_callback":"oob"
    }
    params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])
    base_string += f"{method}&{quote_plus(url)}&{quote(params_string)}"
    encoded_base_string = base_string.encode("utf-8")
    sha256_hash = SHA256.new(data=encoded_base_string)
    bytes_pkcs115_signature = PKCS1_v1_5_Signature.new(
        rsa_key=signature_key
        ).sign(msg_hash=sha256_hash)
    b64_str_pkcs115_signature = base64.b64encode(bytes_pkcs115_signature).decode("utf-8")
    oauth_params['oauth_signature'] = quote_plus(b64_str_pkcs115_signature)
    oauth_params["realm"] = realm
    oauth_header = "OAuth " + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])
    headers = {"Authorization": oauth_header}
    headers["User-Agent"] = "python/3.11"
    lst_request = requests.Request(method=method, url=url, headers=headers)
    lst_response = session_object.send(lst_request.prepare())
    # print(pretty_request_response(lst_response))
    if not lst_response.ok:
        print(f"ERROR: Request to /live_session_token failed. Exiting...")
        raise SystemExit(0)
    response_data = lst_response.json()
    dh_response = response_data["diffie_hellman_response"]
    lst_signature = response_data["live_session_token_signature"]
    lst_expiration = response_data["live_session_token_expiration"]

    # Calculate Live Session Token
    prepend_bytes = bytes.fromhex(prepend)
    a = dh_random
    B = int(dh_response, 16)
    p = dh_prime
    K = pow(B, a, p)
    hex_str_K = hex(K)[2:]
    if len(hex_str_K) % 2:
        print("adding leading 0 for even number of chars")
        hex_str_K = "0" + hex_str_K
    hex_bytes_K = bytes.fromhex(hex_str_K)
    if len(bin(K)[2:]) % 8 == 0:
        hex_bytes_K = bytes(1) + hex_bytes_K
    bytes_hmac_hash_K = HMAC.new(
        key=hex_bytes_K,
        msg=prepend_bytes,
        digestmod=SHA1,
        ).digest()
    computed_lst = base64.b64encode(bytes_hmac_hash_K).decode("utf-8")
    hex_str_hmac_hash_lst = HMAC.new(
        key=base64.b64decode(computed_lst),
        msg=consumer_key.encode("utf-8"),
        digestmod=SHA1,
    ).hexdigest()
    if hex_str_hmac_hash_lst == lst_signature:
        live_session_token = computed_lst
        lst_expiration = lst_expiration
        # print("Live session token computation and validation successful.")
        # print(f"LST: {live_session_token}; expires: {datetime.fromtimestamp(lst_expiration/1000)}\n")
    else:
        print(f"ERROR: LST validation failed. Exiting...")
        raise SystemExit(0)
        

    # Clear Session & Logout
    method = 'GET'
    url = f'https://{BASE_URL}/logout'
    oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_nonce": hex(random.getrandbits(128))[2:],
            "oauth_signature_method": "HMAC-SHA256",
            "oauth_timestamp": str(int(datetime.now().timestamp())),
            "oauth_token": access_token
        }
    params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])
    base_string = f"{method}&{quote_plus(url)}&{quote(params_string)}"
    bytes_hmac_hash = HMAC.new(
        key=base64.b64decode(live_session_token), 
        msg=base_string.encode("utf-8"),
        digestmod=SHA256
        ).digest()
    b64_str_hmac_hash = base64.b64encode(bytes_hmac_hash).decode("utf-8")
    oauth_params["oauth_signature"] = quote_plus(b64_str_hmac_hash)
    oauth_params["realm"] = realm
    oauth_header = "OAuth " + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])
    headers = {"Authorization": oauth_header}
    headers["User-Agent"] = "python/3.11"
    logout_request = requests.Request(method=method, url=url, headers=headers)
    logout_response = session_object.send(logout_request.prepare())
    # print(pretty_request_response(logout_response))


    # Initialize Session
    method = 'GET'
    url = f'https://{BASE_URL}/iserver/auth/ssodh/init?publish=True&compete=True'
    oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_nonce": hex(random.getrandbits(128))[2:],
            "oauth_signature_method": "HMAC-SHA256",
            "oauth_timestamp": str(int(datetime.now().timestamp())),
            "oauth_token": access_token
        }
    params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])
    base_string = f"{method}&{quote_plus(url)}&{quote(params_string)}"
    bytes_hmac_hash = HMAC.new(
        key=base64.b64decode(live_session_token), 
        msg=base_string.encode("utf-8"),
        digestmod=SHA256
        ).digest()
    b64_str_hmac_hash = base64.b64encode(bytes_hmac_hash).decode("utf-8")
    oauth_params["oauth_signature"] = quote_plus(b64_str_hmac_hash)
    oauth_params["realm"] = realm
    oauth_header = "OAuth " + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])
    headers = {"Authorization": oauth_header}
    headers["User-Agent"] = "python/3.11"
    init_request = requests.Request(method=method, url=url, headers=headers)
    init_response = session_object.send(init_request.prepare())
    print(pretty_request_response(init_response))

    # Call Market Scanner & Establish Conids
    method = 'POST'
    url = f'https://{BASE_URL}/hmds/scanner'
    oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_nonce": hex(random.getrandbits(128))[2:],
            "oauth_signature_method": "HMAC-SHA256",
            "oauth_timestamp": str(int(datetime.now().timestamp())),
            "oauth_token": access_token
        }
    params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])
    base_string = f"{method}&{quote_plus(url)}&{quote(params_string)}"
    bytes_hmac_hash = HMAC.new(
        key=base64.b64decode(live_session_token), 
        msg=base_string.encode("utf-8"),
        digestmod=SHA256
        ).digest()
    b64_str_hmac_hash = base64.b64encode(bytes_hmac_hash).decode("utf-8")
    oauth_params["oauth_signature"] = quote_plus(b64_str_hmac_hash)
    oauth_params["realm"] = realm
    oauth_header = "OAuth " + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])
    headers = {"Authorization": oauth_header}
    headers["User-Agent"] = "python/3.11"
    scan_body = {
        "instrument":"STK",
        "locations": "STK.US.MAJOR",
        "scanCode": "HOT_BY_VOLUME",
        "secType": "STK",
        "filters":[{}]
    }
    requests.request(method=method, url=url, headers=headers, json=scan_body)
    scanner_request = requests.request(method=method, url=url, headers=headers, json=scan_body)
    contracts = scanner_request.json()["Contracts"]["Contract"]
    conids = []
    for i in range(len(contracts)):
        conids.append(str(contracts[i]["contractID"]))
    # print(pretty_request_response(tickle_request))
    global CONIDS
    CONIDS = conids


    # Call Tickle for session token.
    method = 'GET'
    url = f'https://{BASE_URL}/tickle'
    oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_nonce": hex(random.getrandbits(128))[2:],
            "oauth_signature_method": "HMAC-SHA256",
            "oauth_timestamp": str(int(datetime.now().timestamp())),
            "oauth_token": access_token
        }
    params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])
    base_string = f"{method}&{quote_plus(url)}&{quote(params_string)}"
    bytes_hmac_hash = HMAC.new(
        key=base64.b64decode(live_session_token), 
        msg=base_string.encode("utf-8"),
        digestmod=SHA256
        ).digest()
    b64_str_hmac_hash = base64.b64encode(bytes_hmac_hash).decode("utf-8")
    oauth_params["oauth_signature"] = quote_plus(b64_str_hmac_hash)
    oauth_params["realm"] = realm
    oauth_header = "OAuth " + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])
    headers = {"Authorization": oauth_header}
    headers["User-Agent"] = "python/3.11"
    tickle_request = requests.request(method=method, url=url, headers=headers)
    # print(pretty_request_response(tickle_request))
    global TICKLE_COOKIE
    TICKLE_COOKIE = tickle_request.json()['session']

def createBook():
    bk = xw.Book()
    bk.save(BN)
    bk.activate(BN)
    

def buildHeaders():
    headers = ["Conid", "Total Responses", "First Response", "Latest Response"]
    for i in range(len(headers)):
      x = letterIncr(i)
      q.put([LD,'{}1'.format(x),headers[i]])

def letterIncr(letterInt):
    incrLetter = chr(ord('@')+letterInt+1)
    return incrLetter

def write_to_workbook():
    while True:
        params = q.get()
        book = params[0]
        cell = params[1]
        content = params[2]
        xw.Book(BN).sheets[book].range(cell).value = content
        print(params)

q = Queue()

for i in range(100):
    t = Thread(
        target=write_to_workbook, 
        daemon=True
      ).start()
q.join()

try:
    xw.Book(BN)
except FileNotFoundError:
    createBook()

repeater = {}

def on_message(ws, message):
    jmsg = json.loads(message.decode('utf-8'))
    cid = jmsg["conidEx"]
    timeNow = f"{datetime.fromtimestamp(int(time.time())).time()}"

    if repeater[cid][2] == '':
        repeater[cid][2] = timeNow
        q.put([LD, 'C{}'.format(repeater[cid][0]), repeater[cid][2]])

    repeater[cid][1] += 1
    repeater[cid][-1] = timeNow

    q.put([LD, 'B{}'.format(repeater[cid][0]), repeater[cid][1]])
    q.put([LD, 'D{}'.format(repeater[cid][0]), repeater[cid][-1]])

def on_error(ws, error):
    print(f"Error: {error}")

def on_close(ws, er1, er2):
    print("##CLOSED##")
    print(er1, er2)

def on_open(ws):
    print("Opened Connection")
    time.sleep(3)
    conids = CONIDS

    for row, conid in enumerate(conids):
        repeater[conid] = [row+2, 0, "", ""] # [row, count, first, latest]
        q.put([LD, 'A{}'.format(row+2), conid])
        
        for col, header in enumerate(repeater[conid]):
            if header != 0:
                x = letterIncr(col+1)
                q.put([LD, '{}{}'.format(x,row+2), header])

        ws.send('smd+'+conid+'+{"fields":["31","84","86"]}')
    print('working so far')


if __name__ == "__main__":
    buildHeaders()
    oauth()
    ws = websocket.WebSocketApp(
        url=f"wss://{BASE_URL}/ws?oauth_token={ACCESS_TOKEN}",
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        header=["User-Agent: python/3.11"],
        cookie=f"api={TICKLE_COOKIE}"
    )
    ws.run_forever()