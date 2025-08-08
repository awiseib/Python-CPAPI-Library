import base64
import json
import pprint
import math
import requests
import time

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

# Used to automatically extract IP address. Can be removed and hardcoded.
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ip = requests.get("https://api.ipify.org", verify=False).text

clientId = 'YOUR_CLIENT_ID_HERE'               # ClientID Provided by Interactive Brokers after registration.                              
clientKeyId = 'main'  
credential = 'YOUR_CREDENTIAL HERE'            # Credential will reflect the username authenticating with.  
path_to_PrivateKey = r"path/to/privatekey.pem" # Path to your private RSA Key for CP API
scope = "sso-sessions.write"
 

#====================================================================================================================
#------------------------------------------BASE URLS-----------------------------------------------------------------
#====================================================================================================================
host = 'api.ibkr.com'
oauth2Url = 'https://api.ibkr.com/oauth2'
gatewayUrl = 'https://api.ibkr.com/gw'
clientPortalUrl = 'api.ibkr.com/v1/api'
audience = '/token'


file = open(path_to_PrivateKey, "r")                                   #Read private RSA Key then close it, once done 
clientPrivateKey = file.read()   
jwtPrivateKey = RSA.import_key(clientPrivateKey.encode()) 
file.close()

# Create a session for HTTP requests
session = requests.Session()
session.headers.update({
    "User-Agent": "python/3.x",
    "Host": "api.ibkr.com"
})

RESP_HEADERS_TO_PRINT = ["Cookie", "Cache-Control", "Content-Type", "Host"]
def pretty_request_response(resp: requests.Response) -> str:
    """Print request and response legibly."""
    req = resp.request
    rqh = '\n'.join(f"{k}: {v}" for k, v in req.headers.items())
    rqh = rqh.replace(', ', ',\n    ')
    
    #rqb = " "
    rqb = req.body if req.body else ""
    #rqb = f"\n{pprint.pformat(json.loads(req.body))}\n" if req.body else ""
    
    try:
        rsb = f"\n{pprint.pformat(resp.json())}\n" if resp.text else ""
    except json.JSONDecodeError:
        rsb = resp.text
    rsh = '\n'.join([f"{k}: {v}" for k, v in resp.headers.items() if k in RESP_HEADERS_TO_PRINT])
    
    return_str = '\n'.join([
        #80*'-',
        '-----------REQUEST-----------',
        f"{req.method} {req.url}",
        "",
        rqh,
        f"{rqb}",
        "",
        '-----------RESPONSE-----------',
        f"{resp.status_code} {resp.reason}",
        rsh,
        f"{rsb}\n",
    ])
    return return_str

def gen_timestamp():
    """Generate a 10-digit Unix timestamp"""
    return int(time.time())

def web_header_print(response: requests.Response):
    """Print request and response details for debugging"""
    print("########## Request ###########")
    request = response.request
    print(f"{request.method} {request.url}")
    print(request.headers)
    if hasattr(request, 'body') and request.body:
        print(request.body)
    
    print("\n########## Response ###########")
    print(f"{response.status_code} {response.reason}")
    print(response.text)
    print("----------------------------\n")

def standard_request( request_method, request_url, bearer_token, req_content="{}"):
    """Send a standard HTTP request with appropriate headers"""
    try:
        headers = {
            "Host": "api.ibkr.com",
            "User-Agent": "python/3.x",
            "Accept": "*/*",
            "Connection": "keep-alive",
            "Authorization": f"Bearer {bearer_token}"
        }
        
        if request_method == "GET":
            response = session.get(request_url, headers=headers)
        else:  # POST
            headers["Content-Type"] = "application/json"
            response = session.post(
                request_url, 
                headers=headers, 
                data=req_content
            )
        
        if response.status_code != 200:
            print(f"Request to {request_url} failed. Received status code {response.status_code}")
            web_header_print(response)
        else:
            web_header_print(response)
            
        return response.text
    except Exception as ex:
        print(str(ex))
        return ""

def base64_encode(val):
    return base64.b64encode(val).decode().replace('+', '-').replace('/', '_').rstrip('=')

def make_jws(header, claims):
    json_header = json.dumps(header, separators=(',', ':')).encode()
    encoded_header = base64_encode(json_header)
    json_claims = json.dumps(claims, separators=(',', ':')).encode()
    encoded_claims = base64_encode(json_claims)

    payload = f"{encoded_header}.{encoded_claims}"
    
    md = SHA256.new(payload.encode())
    signer = PKCS1_v1_5.new(jwtPrivateKey)
    signature = signer.sign(md)
    encoded_signature = base64_encode(signature)
    
    return payload + "." + encoded_signature

def compute_client_assertion(url):
    now = math.floor(time.time())
    header = {
        'alg': 'RS256',
        'typ': 'JWT',
        'kid': f'{clientKeyId}'
    }

    if url == f'{oauth2Url}/api/v1/token':
        claims = {
            'iss': f'{clientId}',
            'sub': f'{clientId}',
            'aud': f'{audience}',
            'exp': now + 20,
            'iat': now - 10
        }

    elif url == f'{gatewayUrl}/api/v1/sso-sessions':
        print(ip)
        claims = {
            'ip': ip,                    
            #'service': "AM.LOGIN",
            'credential': f'{credential}',
            'iss': f'{clientId}',
            'exp': now + 86400,
            'iat': now
        }

    assertion = make_jws(header, claims)
    return assertion


#====================================================================================================================
#---------------------------------1. REQUEST OAuth 2.0 ACCESS TOKEN--------------------------------------------------
#====================================================================================================================
def getAccessToken():
    url=f'{oauth2Url}/api/v1/token'

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    form_data = {
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': compute_client_assertion(url),
            'grant_type': 'client_credentials',
            'scope': scope
    }

    token_request = requests.post(url=url, headers=headers, data=form_data)
    print(web_header_print(token_request))
    
    return token_request.json()["access_token"]


#====================================================================================================================
#--------------------------------2. REQUEST SSO BEARER TOKEN---------------------------------------------------------
#====================================================================================================================
def getBearerToken(access_token: str):
    url=f'{gatewayUrl}/api/v1/sso-sessions'

    headers = {
        "Authorization": "Bearer " + access_token,
        "Content-Type": "application/jwt"
    }

    signed_request = compute_client_assertion(url)
    bearer_request = requests.post(url=url, headers=headers, data=signed_request)
    print(web_header_print(bearer_request))
    
    if bearer_request.status_code == 200:
        return bearer_request.json()["access_token"]
    return

if __name__ == "__main__":
    """Main method to execute the OAuth2 flow"""
    # Request #1: Request an Access Token
    accessToken = getAccessToken()
    
    # Request #2: Request a Bearer Token using our Access Token
    bearerToken = getBearerToken(accessToken)
    
    # Request #3: Initialize Brokerage Session
    endpoint = "/iserver/auth/ssodh/init"
    req_content = json.dumps({"compete": True, "publish": True})
    standard_request("POST", f"https://{clientPortalUrl}{endpoint}", bearerToken, req_content)
    
    # The system needs a moment to spin up before making requests
    time.sleep(1)
    
    # Request #4: Confirm valid accounts within the portfolio
    endpoint = "/iserver/accounts"
    standard_request("GET", f"https://{clientPortalUrl}{endpoint}", bearerToken)
