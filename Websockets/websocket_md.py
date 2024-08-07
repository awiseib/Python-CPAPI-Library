import websocket
import time
import ssl

def on_message(ws, message):
    print(message)

def on_error(ws, error):
    print(error)

def on_close(ws):
    print("## CLOSED! ##")

def on_open(ws):
    print("Opened Connection")
    time.sleep(3)
    conids = ["8314"]

    for conid in conids:
        ws.send('smd+'+conid+'+{"fields":["31","84","86"]}')

if __name__ == "__main__":
    ws = websocket.WebSocketApp(
        url="wss://localhost:5000/v1/api/ws",
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    ws.run_forever(sslopt={"cert_reqs":ssl.CERT_NONE})

'''
Users without a signed server certificate should pass
> sslopt={"cert_reqs":ssl.CERT_NONE}
as an argument to ws.run_forever()
'''