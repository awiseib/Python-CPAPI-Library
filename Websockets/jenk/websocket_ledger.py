import websocket
import time
import ssl
import json


"""
This is based on internal code and is not a valid topic.
Calls to this method will not show an error, but will never display positions data.
"""

def on_message(ws, message):
    print(message)

def on_error(ws, error):
    print(error)

def on_close(ws):
    print("## CLOSED! ##")

def on_open(ws):
    print("Opened Connection")
    time.sleep(3)
    ws.send('sld+DU524065') # Could also be sps+DU5240685 // spd+DU5240685 // rpl+DU524065

if __name__ == "__main__":
    ws = websocket.WebSocketApp(
        url="wss://localhost:5000/v1/api/ws",
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    ws.run_forever(sslopt={"cert_reqs":ssl.CERT_NONE})