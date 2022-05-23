import http.client
import time

try:

  while True:
      for req in range(10):
          conn = http.client.HTTPConnection("10.0.0.5")
          conn.request("GET", "/")
          resp = conn.getresponse()
          print(resp.status, resp.reason)
          conn.close()
          time.sleep(1)
      print("====================")
      time.sleep(10)

except KeyboardInterrupt:
  print("CTRL-C - Exiting...")
  exit(0)

except:
  print("No route to Server. Exiting")
  exit(1)

