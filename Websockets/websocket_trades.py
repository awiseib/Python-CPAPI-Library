import websocket
import time
import ssl
import json

def on_message(ws, message):
    jmsg = json.loads(message.decode('utf-8'))
    try:
        if "args" in jmsg:
            print(f"\nTopic: {jmsg['topic']}")
            for i in jmsg['args']:
                print(f"Content: {i}")
    except:
        print("Try failed...")
        print(jmsg)

def on_error(ws, error):
    print(error)

def on_close(ws):
    print("## CLOSED! ##")

def on_open(ws):
    print("Opened Connection")
    time.sleep(3)
    ws.send('str+{"days":1}')

if __name__ == "__main__":
    ws = websocket.WebSocketApp(
        url="wss://localhost:5000/v1/api/ws",
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    ws.run_forever(sslopt={"cert_reqs":ssl.CERT_NONE})