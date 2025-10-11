# server.py
from http.server import HTTPServer, BaseHTTPRequestHandler

class SimpleHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print("\n--- Server received data ---")
        print(post_data.decode('utf-8'))
        print("---------------------------\n")
        
        # Send a response back to the browser
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Data received by local server!')

print("[*] Starting local test server on http://localhost:8000")
server = HTTPServer(('localhost', 8000), SimpleHandler)
server.serve_forever()