import websocket
import time
import ssl

def on_message(ws, message):
    print(message)

def on_error(ws, error):
    print(f"error: {error}")

def on_close(ws):
    print("### closed ###")

def on_open(ws):
    print("Opened connection")
    time.sleep(3)
    conids = ["265598", "8314", "8894", "4815747", "76792991", "14094"] # AAPL, IBM, KO, NVDA, TSLA, BMW
    for conid in conids:
        ws.send('smh+'+conid+'+{"exchange":"ISLAND","period":"1d","bar":"1d","outsideRth":false,"source":"trades"}')
    unsubs = ["1211461", "1211462", "1211460"]
    for sub in unsubs:
        ws.send(f'umh+{sub}')


if __name__ == "__main__":
    ws = websocket.WebSocketApp("wss://localhost:5000/v1/api/ws",
                                on_open = on_open,
                                on_message = on_message,
                                on_error = on_error,
                                on_close = on_close)

    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})