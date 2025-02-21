import requests
import json

def ib_print(resp: requests.Response) -> str:
    resp_headers = ["Content-Type", "Content-Length", "Date", "Set-Cookie", "User-Agent"]

    """Print request and response legibly."""
    req = resp.request
    rqh = '\n'.join(f"{k}: {v}" for k, v in req.headers.items())
    rqh = rqh.replace(', ', ',\n    ')
    rqb = f"\n{json.dumps(req.body, indent=2)}\n" if req.body else ""
    try:
        rsb = f"\n{json.dumps(resp.json(), indent=2)}\n" if resp.text else ""
    except json.JSONDecodeError:
        rsb = resp.text
    rsh = '\n'.join([f"{k}: {v}" for k, v in resp.headers.items() if k in resp_headers])
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
    print(return_str)
    return