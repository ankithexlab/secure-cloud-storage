# =============================================================================
# serve_frontend.py — Lightweight SPA HTTP server for production build
# =============================================================================
import os
import http.server
import socketserver

PORT = 3000
DIRECTORY = os.path.join(os.path.dirname(__file__), 'build')

class SPAHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        path = self.translate_path(self.path)
        if not os.path.exists(path) and not os.path.splitext(path)[1]:
            self.path = '/index.html'
        return super().do_GET()

if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), SPAHandler) as httpd:
        print(f"Frontend server running at http://localhost:{PORT}")
        httpd.serve_forever()
