import http.server
import socketserver
import traceback
PORT = 80

try:

  Handler = http.server.SimpleHTTPRequestHandler

  with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()

except KeyboardInterrupt:
  print("CTRL-C - Exiting...")
  exit(0)

except:
  print("No route to Server. Exiting")
  traceback.print_exc()
  exit(1)

