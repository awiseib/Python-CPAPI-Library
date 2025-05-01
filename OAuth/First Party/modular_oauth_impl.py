"""
Slightly more complex implementation though provides easier request 
structure and an authentication check to avoid duplicate authentication.

Requires Python packages: pycryptodome, requests

Enter configuration values in Prequisites section below before running.
"""

import base64
from datetime import datetime
import json
import pickle
import pprint
import random
import requests
import requests.adapters
import time
import websocket

from urllib.parse import quote, quote_plus
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signature
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Hash import SHA256, HMAC, SHA1

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

# -------------------------------------------------------------------
# Prequisites: Enter paths to keys and access token/secret below
# -------------------------------------------------------------------

# I have a JSON file contianing my credentials.
# You will need to replace the filepath to recognize your own. 
# Alternatively, create a string directly linking to the various PEM files or strings referenced. 
credentials = json.load(open(file=r"C:\Users\awise\Code\credentials.json", mode="r"))
current_user = credentials['user1']

# Replace with path to private encryption key file.
with open(current_user['encryption'], "r") as f:
    encryption_key = RSA.importKey(f.read())

# Replace with path to private signature key file.
with open(current_user['signature'], "r") as f:
    signature_key = RSA.importKey(f.read())

# Replace with path to DH param PEM file.
with open(current_user['dhparam'], "r") as f:
    dh_param = RSA.importKey(f.read())
    dh_prime = dh_param.n # Also known as DH Modulus
    dh_generator = dh_param.e  # always =2

# Enter your access token and access token secret here.
access_token = current_user['access_token']
access_token_secret = current_user['access_token_secret']

# If substituting your own consumer key created via the Self-Service Portal,
# change realm to "limited_poa" (test_realm is for TESTCONS only).
consumer_key = current_user['consumer_key']
realm = "test_realm" if consumer_key == "TESTCONS" else "limited_poa"

baseUrl = "api.ibkr.com/v1/api" # LIVE

# -------------------------------------------------------------------
# Request #0: Validate potentially existing live session tokens
# -------------------------------------------------------------------
def awise_auth(genNewKey=False):
    pickle_jar = current_user['dhparam'][:-11] + f"{consumer_key}.pickle"
    
    try:
        with open(file= pickle_jar, mode="rb") as f:
            pickles = pickle.load(file=f)
            if pickles["expiration"] >= time.time()*1000 and genNewKey == False:
                return pickles["lst"]
    except FileNotFoundError:
        print("File not found. Generating Pickle Jar")
    
    print("Generating new Live Session Token")
    # Request our Live Session Token value
    dh_random, prepend, dh_response, lst_signature, lst_expiration = get_lst()
    # Compute the LST based on our diffie-hellman response
    computed_lst = compute_lst(dh_random, prepend, dh_response)
    # Validate that our calculated LST matches the server response
    # This is technically an optional step; however, future attempted requests might otherwise fail.
    lst = validate_lst(lst_signature, lst_expiration, computed_lst)

    lst_pickle = {"lst": lst, "expiration": lst_expiration}
    with open(file= pickle_jar, mode="wb") as f:
        pickle.dump(obj=lst_pickle, file=f)
    return lst


# -------------------------------------------------------------------
# Request #1: Obtaining a LST
# -------------------------------------------------------------------
def get_lst():
    # Generate a random 256-bit integer.
    dh_random = random.getrandbits(256)

    # Compute the Diffie-Hellman challenge:
    # generator ^ dh_random % dh_prime
    # Note that IB always uses generator = 2.
    # Convert result to hex and remove leading 0x chars.
    dh_challenge = hex(pow(base=dh_generator, exp=dh_random, mod=dh_prime))[2:]
    # --------------------------------
    # Generate LST request signature.
    # --------------------------------

    # Generate the base string prepend for the OAuth signature:
    #   Decrypt the access token secret bytestring using private encryption
    #   key as RSA key and PKCS1v1.5 padding.
    #   Prepend is the resulting bytestring converted to hex str.
    bytes_decrypted_secret = PKCS1_v1_5_Cipher.new(
        key=encryption_key
        ).decrypt(
            ciphertext=base64.b64decode(access_token_secret), 
            sentinel=None,
            )
    prepend = bytes_decrypted_secret.hex()

    # Put prepend at beginning of base string str.
    base_string = prepend
    # Elements of the LST request so far.
    method = 'POST'
    url = f'https://{baseUrl}/oauth/live_session_token'
    oauth_params = {
        "oauth_consumer_key": consumer_key,
        "oauth_nonce": hex(random.getrandbits(128))[2:],
        "oauth_timestamp": str(int(datetime.now().timestamp())),
        "oauth_token": access_token,
        "oauth_signature_method": "RSA-SHA256",
        "diffie_hellman_challenge": dh_challenge,
    }

    # Combined param key=value pairs must be sorted alphabetically by key
    # and ampersand-separated.
    params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])

    # Base string = method + url + sorted params string, all URL-encoded.
    base_string += f"{method}&{quote_plus(url)}&{quote_plus(params_string)}"
    
    # Convert base string str to bytestring.
    encoded_base_string = base_string.encode("utf-8")
    # Generate SHA256 hash of base string bytestring.
    sha256_hash = SHA256.new(data=encoded_base_string)

    # Generate bytestring PKCS1v1.5 signature of base string hash.
    # RSA signing key is private signature key.
    bytes_pkcs115_signature = PKCS1_v1_5_Signature.new(
        rsa_key=signature_key
        ).sign(msg_hash=sha256_hash)

    # Generate str from base64-encoded bytestring signature.
    b64_str_pkcs115_signature = base64.b64encode(bytes_pkcs115_signature).decode("utf-8")

    # URL-encode the base64 signature str and add to oauth params dict.
    oauth_params['oauth_signature'] = quote_plus(b64_str_pkcs115_signature)

    # Oauth realm param omitted from signature, added to header afterward.
    # oauth_params["realm"] = realm

    # Assemble oauth params into auth header value as comma-separated str.
    oauth_header = f"OAuth realm={realm}, " + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])

    # Create dict for LST request headers including OAuth Authorization header.
    headers = {"Authorization": oauth_header}

    # Add User-Agent header, required for all requests. Can have any value.
    headers["User-Agent"] = "python/3.11"

    # Prepare and send request to /live_session_token, print request and response.
    lst_request = requests.post(url=url, headers=headers)
    print(pretty_request_response(lst_request))
    # Check if request returned 200, proceed to compute LST if true, exit if false.
    if not lst_request.ok:
        print(f"ERROR: Request to /live_session_token failed. Exiting...")
        raise SystemExit(0)

    # Script not exited, proceed to compute LST.
    response_data = lst_request.json()
    dh_response = response_data["diffie_hellman_response"]
    lst_signature = response_data["live_session_token_signature"]
    lst_expiration = response_data["live_session_token_expiration"]

    return dh_random, prepend, dh_response, lst_signature, lst_expiration

# -------------
# Compute LST.
# -------------
def compute_lst(dh_random, prepend, dh_response):
    # Generate bytestring from prepend hex str.
    prepend_bytes = bytes.fromhex(prepend)

    # Convert hex string response to integer and compute K=B^a mod p.
    # K will be used to hash the prepend bytestring (the decrypted 
    # access token) to produce the LST.
    a = dh_random
    B = int(dh_response, 16)
    p = dh_prime
    K = pow(B, a, p)

    # Generate hex string representation of integer K.
    hex_str_K = hex(K)[2:]

    # If hex string K has odd number of chars, add a leading 0, 
    # because all Python hex bytes must contain two hex digits 
    # (0x01 not 0x1).
    if len(hex_str_K) % 2:
        print("adding leading 0 for even number of chars")
        hex_str_K = "0" + hex_str_K

    # Generate hex bytestring from hex string K.
    hex_bytes_K = bytes.fromhex(hex_str_K)

    # Prepend a null byte to hex bytestring K if lacking sign bit.
    if len(bin(K)[2:]) % 8 == 0:
        hex_bytes_K = bytes(1) + hex_bytes_K
    
    # Generate bytestring HMAC hash of hex prepend bytestring.
    # Hash key is hex bytestring K, method is SHA1.
    bytes_hmac_hash_K = HMAC.new(
        key=hex_bytes_K,
        msg=prepend_bytes,
        digestmod=SHA1,
        ).digest()

    # The computed LST is the base64-encoded HMAC hash of the
    # hex prepend bytestring.
    # Converted here to str.
    computed_lst = base64.b64encode(bytes_hmac_hash_K).decode("utf-8")
    return computed_lst

# -------------
# Validate LST
# -------------
def validate_lst(lst_signature, lst_expiration, computed_lst):
    # Generate hex-encoded str HMAC hash of consumer key bytestring.
    # Hash key is base64-decoded LST bytestring, method is SHA1.
    hex_str_hmac_hash_lst = HMAC.new(
        key=base64.b64decode(computed_lst),
        msg=consumer_key.encode("utf-8"),
        digestmod=SHA1,
    ).hexdigest()

    # If our hex hash of our computed LST matches the LST signature
    # received in response, we are successful.
    if hex_str_hmac_hash_lst == lst_signature:
        live_session_token = computed_lst
        print("Live session token computation and validation successful.")
        print(f"LST: {live_session_token}; expires: {datetime.fromtimestamp(lst_expiration/1000)}\n")
        return live_session_token
    else:
        print(f"ERROR: LST validation failed. Exiting...")
        raise SystemExit(0)

def standard_request(live_session_token, method: str, endpoint: str, query_params={}, content={}, print_data="y"):
    # Initial, non-computed elements of request to /portfolio/accounts.
    url = f'https://{baseUrl}{endpoint}'
    oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_nonce": hex(random.getrandbits(128))[2:],
            "oauth_signature_method": "HMAC-SHA256",
            "oauth_timestamp": str(int(datetime.now().timestamp())),
            "oauth_token": access_token
        }

    # ----------------------------------
    # Generate request OAuth signature.
    # ----------------------------------

    # Combined param key=value pairs must be sorted alphabetically by key
    # and ampersand-separated.
    params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])

    # Base string = method + url + sorted params string, all URL-encoded.
    base_string = f"{method}&{quote_plus(url)}&{quote(params_string)}"

    # Generate bytestring HMAC hash of base string bytestring.
    # Hash key is base64-decoded LST bytestring, method is SHA256.
    bytes_hmac_hash = HMAC.new(
        key=base64.b64decode(live_session_token), 
        msg=base_string.encode("utf-8"),
        digestmod=SHA256
        ).digest()

    # Generate str from base64-encoded bytestring hash.
    b64_str_hmac_hash = base64.b64encode(bytes_hmac_hash).decode("utf-8")

    # URL-encode the base64 hash str and add to oauth params dict.
    oauth_params["oauth_signature"] = quote_plus(b64_str_hmac_hash)

    # Oauth realm param omitted from signature, added to header afterward.
    oauth_params["realm"] = realm

    # Assemble oauth params into auth header value as comma-separated str.
    oauth_header = "OAuth " + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])

    # Create dict for LST request headers including OAuth Authorization header.
    headers = {"Authorization": oauth_header}

    # Add User-Agent header, required for all requests. Can have any value.
    headers["User-Agent"] = "python/3.11"
    headers["Accept"] = "*/*"
    headers["Connection"] = "keep-alive"

    s = requests.Session()
    retries = requests.adapters.Retry(
        total=5
        # backoff_factor=0.1,
        # status_forcelist=[ 500, 502, 503, 504 ]
        )
    s.mount("https://", requests.adapters.HTTPAdapter(max_retries=retries))

    try:
        with s.request(method=method, url=url, headers=headers, params=query_params, json=content, timeout=1000, stream=True) as req:
            if print_data == "y":
                print(pretty_request_response(req))
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
        ws.send('sor+{}')
        ws.send('smd+265598+{"fields":["55","31","82","83","87","7762"]}')

def on_error(ws, error):
    print(f"Error received: {error}")

def on_close(ws, r1, r2):
    print("## CLOSED! ##")
    print(f"r1:{r1}")
    print(f"r2:{r2}")

def on_open(ws):
    print("Opened Connection")
    
if __name__ == "__main__":
    accountId = ""
    # Authentication implementation to see if I need to generate a live session token or if existing token can be reused. 
    lst = awise_auth()

    # Initialize our brokerage session so we can make market data requests and place trades.
    standard_request(
        live_session_token=lst, 
        method="POST", 
        endpoint="/iserver/auth/ssodh/init",
        content={"compete": True, "publish": True}
        )
    time.sleep(3)

    # Find the default account for the strucutre
    accountId  = standard_request(
        live_session_token=lst, 
        method="GET", 
        endpoint=f"/iserver/accounts"
    ).json()["selectedAccount"]

    # Ignores order precautions to expedite order submission flow. 
    standard_request(
        live_session_token=lst, 
        method="POST", 
        endpoint="/iserver/questions/suppress", 
        content={"messageIds":["o10164","o10223","o403","o10331","o2137","o10082","o10332","o10333","o10334","o2136","o10335","o10151","o10288","o10152","o10153","o2165","p12","o354","o383","o451","o10138","o163","o382", "o354"]}
    )
    
    time.sleep(3)

    # submit a What If order in case 
    standard_request(
        live_session_token=lst, 
        method="POST", 
        endpoint=f"/iserver/account/{accountId}/orders/whatif", 
        content={"orders":[{"conidex":"265598", "quantity": 1, "side":"BUY", "orderType":"MKT", "tif":"DAY"}]}
        )     

    # Get the session token to init the websocket.
    session_token = standard_request(
        live_session_token=lst, 
        method="POST", 
        endpoint="/tickle"
        ).json()["session"]

    # Initiate our Websocket, passing our Access token as a query param
    # Be sure to pass the session token from /tickle as a cookie header for the session.
    ws = websocket.WebSocketApp(
        url=f"wss://{baseUrl}/ws?oauth_token={access_token}",
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        header=["User-Agent: python/3.11"],
        cookie=f"api={session_token}"
    )
    
    ws.run_forever()
