import websocket
import time
import ssl

def on_message(ws, message):
    print(message)

def on_error(ws, error):
    print(error)

def on_close(ws):
    print("### closed ###")

def on_open(ws):
    print("Opened connection")
    time.sleep(1)
    acctId = "DU5240685"
    myConids = ["589141849"]
    for i in myConids:
        ws.send('sbd+'+acctId+'+'+i)
        time.sleep(1)

if __name__ == "__main__":
    ws = websocket.WebSocketApp("wss://localhost:5001/v1/api/ws",
                                on_open = on_open,
                                on_message = on_message,
                                on_error = on_error,
                                on_close = on_close)

    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})