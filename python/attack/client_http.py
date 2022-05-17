import http.client
import time

while True:
    for req in range(10):
        conn = http.client.HTTPConnection("10.0.0.5")
        conn.request("GET", "/")
        resp = conn.getresponse()
        print(resp.status, resp.reason)
        conn.close()
        time.sleep(0.1)
    print("====================")
    time.sleep(10)

