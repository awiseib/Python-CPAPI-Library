"""
Simple test script to demonstrate generating and using a Live Session Token
in a first-party OAuth context. Assumes access token and access token secret
have been generated and stored via IB's nodeJS OAuth demo or OAuth Self-Service 
Portal.
Requires Python packages: pycryptodome, requests
Enter configuration values in Prequisites section below before running.
"""
import json
import requests
import random
import base64
from datetime import datetime
from urllib.parse import quote, quote_plus
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signature
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Hash import SHA256, HMAC, SHA1
import websocket
import time

key_dir = "D:\Code\Oauth_Demo\web.demo\keys\\"
with open(key_dir+"private_encryption.pem", "r") as f:
  encryption_key = RSA.import_key(f.read())

with open(key_dir+"private_signature.pem", "r") as f:
  signature_key = RSA.import_key(f.read())

dh_prime = "f51d7ab737a452668fd8b5eec12fcdc3c01a0744d93db2e9b1dc335bd2551ec67e11becc60c33a73497a0f7c086d87e45781ada35b7af72708f31ae221347a1c6517575a347df83a321d05450547ee13a8182280ed81423002aa6337b48a251d840bfdabe8d41b8109284933a6c33bc6652ea9c7a5fd6b4945b7b39f1d951ae19b9192061e2f9de84768b67c425258724cdb96975917cabdea87e7e0bc72b01a331d06f2f34229a5ec742b399fcffa510bf6b8f9b5bf9858f058371a49aa4f950f7fbfb3f47710af34baa83fff1b467d38d0e6b1b0a2d117f178cf930d7dfdcc8f6755a2229d48492a967f493041121e382b9e87ca1368c09f54e6352d909f2b"
dh_generator = 2

consumer_key = "TESTCONS"
realm = "test_realm"
baseUrl = "api.ibkr.com/v1/api"
callback = "oob"

###########
# Obtaining Request Token
###########
def request_token():
  url = f'https://{baseUrl}/oauth/request_token'
  oauth_params = {
    "oauth_callback":callback,
    "oauth_consumer_key": consumer_key,
    "oauth_nonce": hex(random.getrandbits(128))[2:],
    "oauth_signature_method": "RSA-SHA256",
    "oauth_timestamp": str(int(datetime.now().timestamp())),
    }
  params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])

  # Base string successfully created
  base_string = f"POST&{quote_plus(url)}&{quote(params_string)}"

  # Base string should then signed with the private key in RSA-SHA256
  encoded_base_string = base_string.encode("utf-8")
  sha256_hash = SHA256.new(data=encoded_base_string)
  bytes_pkcs115_signature = PKCS1_v1_5_Signature.new(
    rsa_key=signature_key
    ).sign(msg_hash=sha256_hash)
  b64_str_pkcs115_signature = base64.b64encode(bytes_pkcs115_signature).decode("utf-8")

  oauth_params["oauth_signature"] = quote_plus(b64_str_pkcs115_signature)
  oauth_params["realm"] = realm
  oauth_header = "OAuth " + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])
  headers = {"authorization": oauth_header}
  headers["User-Agent"] = "python/3.11"
  
  request_request = requests.post(url=url, headers=headers)
  
  if request_request.status_code == 200:
    request_response = json.dumps(request_request.json(), indent=2)
    print(request_response)
    rToken = request_request.json()["oauth_token"]
  else:
    print("Failed to retrieve Request Token")
    print(f"{request_request.status_code}: {request_request.content}")
    print(request_request.request.headers)
  
  return rToken

###########
# Retrieve the Verifier token
###########
def authorize(rToken):
  url = f'https://interactivebrokers.com/authorize?oauth_token={rToken}'
  verifier = input(f"Please log in to {url} and paste the 'oauth_verifier' value here: ")
  return verifier

###########
# Obtaining Access Token and Access Token Secret
###########
def access_tokens(rToken, vToken):
  url = f'https://{baseUrl}/oauth/access_token'
  oauth_params = {
    "oauth_callback":callback,
    "oauth_consumer_key": consumer_key,
    "oauth_nonce": hex(random.getrandbits(128))[2:],
    "oauth_signature_method": "RSA-SHA256",
    "oauth_timestamp": str(int(datetime.now().timestamp())),
    "oauth_token": rToken,
    "oauth_verifier": vToken,
    }
  params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])

  # Base string successfully created
  base_string = f"POST&{quote_plus(url)}&{quote(params_string)}"

  # Base string should then signed with the private key in RSA-SHA256
  encoded_base_string = base_string.encode("utf-8")
  sha256_hash = SHA256.new(data=encoded_base_string)
  bytes_pkcs115_signature = PKCS1_v1_5_Signature.new(
    rsa_key=signature_key
    ).sign(msg_hash=sha256_hash)
  b64_str_pkcs115_signature = base64.b64encode(bytes_pkcs115_signature).decode("utf-8")

  oauth_params["oauth_signature"] = quote_plus(b64_str_pkcs115_signature)
  oauth_params["realm"] = realm
  oauth_header = "OAuth " + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])
  headers = {"authorization": oauth_header}
  headers["User-Agent"] = "python/3.11"
  
  request_request = requests.post(url=url, headers=headers)
  
  if request_request.status_code == 200:
    request_response = json.dumps(request_request.json(), indent=2)
    print(request_response)
    aToken = request_request.json()["oauth_token"]
    aToken_secret = request_request.json()["oauth_token_secret"]
  else:
    print(f"{request_request.status_code}: {request_request.content}")
    print(request_request.request.headers )
  
  return aToken, aToken_secret

#########
# Generate a live session token to establish a connection
#############
def generate_lst(access_token, access_token_secret):
  dh_random = str(random.getrandbits(256))
  dh_unchallenged = pow(dh_generator, int(dh_random, 16), int(dh_prime, 16))
  dh_challenge = hex(dh_unchallenged)[2:]
  bytes_decrypted_secret = PKCS1_v1_5_Cipher.new(
    key=encryption_key
    ).decrypt(
      ciphertext=base64.b64decode(access_token_secret), 
      sentinel=None,
      )
  prepend = bytes_decrypted_secret.hex()
  base_string = prepend
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
  lst_request = requests.post(url=url, headers=headers)
  lst_response = json.dumps(lst_request.json())
  if lst_request.status_code != 200:
    print(f"ERROR: Request to /live_session_token failed. Exiting...")
    raise SystemExit(0)
  response_data = lst_request.json()
  print(json.dumps(response_data, indent=2))
  dh_response = response_data["diffie_hellman_response"]
  lst_signature = response_data["live_session_token_signature"]
  lst_expiration = response_data["live_session_token_expiration"]

  prepend_bytes = bytes.fromhex(prepend)

  INT_BASE = 16
  B = int(dh_response, INT_BASE)
  a = int(dh_random, INT_BASE)
  p = int(dh_prime, INT_BASE)
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
    print("Live session token computation and validation successful.")
    print(f"LST: {live_session_token}; expires: {datetime.fromtimestamp(lst_expiration/1000)}\n")
    return live_session_token
  else:
    print(f"ERROR: LST validation failed. Exiting...")
    raise SystemExit(0)
  
#########
# Logout to purge old sessions
########
def logout(access_token, live_session_token):
  method = "GET"
  url = f'https://{baseUrl}/logout'
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
  logout_request = requests.post(url=url, headers=headers)
  try:
    logout_response = json.dumps(logout_request.json(), indent=2)
    print(logout_response)
  except:
    print(f"Logout: {logout_request.status_code}")

########
# initialize session
##########
def init_session(access_token, live_session_token):
  method = "POST"
  url = f'https://{baseUrl}/iserver/auth/ssodh/init?publish=true&compete=true'
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
  init_request = requests.post(url=url, headers=headers)
  init_response = json.dumps(init_request.json(), indent=2)
  print(init_response)

###########
# Tickle ##
###########
def tickle(access_token, live_session_token):
  method = "GET"
  url = f'https://api.ibkr.com/tickle'
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
  tickle_request = requests.get(url=url, headers=headers)
  session_token = tickle_request.json()['session']
  print(session_token)
  return session_token

if __name__ == "__main__":
  rToken = request_token()
  vToken = authorize(rToken)
  aToken, aToken_secret = access_tokens(rToken, vToken)
  lst = generate_lst(aToken, aToken_secret)
  logout(aToken, lst)
  init_session(aToken, lst)
  # tickle(aToken, lst)