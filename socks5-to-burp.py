import socket
import select
import struct
import socketserver
import threading
import logging
import time

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

SOCKS_VERSION = 5

def connect_via_burp(host, port):
    """Connect to the target host:port via Burp's HTTP proxy using CONNECT method."""
    logging.debug(f"Connecting to Burp at 127.0.0.1:8080 for {host}:{port}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(('127.0.0.1', 8080))
        connect_header = (
            f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"\r\n"
        )
        s.sendall(connect_header.encode('utf-8'))
        response = b""
        while True:
            data = s.recv(8000)
            if not data:
                raise Exception("No response from Burp")
            response += data
            if b"\r\n\r\n" in response:
                break
        logging.debug(f"Burp response: {response.decode('utf-8', errors='ignore')}")
        if b"200 Connection established" not in response:
            raise Exception(f"CONNECT failed: {response.decode('utf-8', errors='ignore')}")
        s.settimeout(None)
        return s
    except Exception as e:
        logging.error(f"Error connecting via Burp for {host}:{port}: {e}")
        raise

class SocksProxy(socketserver.StreamRequestHandler):
    def handle(self):
        logging.info(f"Handling connection from {self.client_address}")
        try:
            # SOCKS5 greeting header
            header = self.connection.recv(2)
            if len(header) != 2:
                logging.error("Invalid greeting header")
                return
            version, nmethods = struct.unpack("!BB", header)
            logging.debug(f"Version: {version}, Methods: {nmethods}")

            if version != SOCKS_VERSION:
                logging.error(f"Unsupported SOCKS version: {version}")
                return

            # Get available methods
            methods = self.get_available_methods(nmethods)
            logging.debug(f"Available methods: {methods}")
            if 0 not in methods:
                self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 255))
                logging.error("No-auth method not supported")
                return

            # Send choice: no authentication
            self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0))

            # SOCKS5 request
            request = self.connection.recv(4)
            if len(request) != 4:
                logging.error("Invalid request header")
                return
            version, cmd, _, address_type = struct.unpack("!BBBB", request)
            logging.debug(f"Request: version={version}, cmd={cmd}, address_type={address_type}")

            if version != SOCKS_VERSION or cmd != 1:
                logging.error(f"Unsupported request: version={version}, cmd={cmd}")
                return

            if address_type == 1:  # IPv4
                address = socket.inet_ntoa(self.connection.recv(4))
            elif address_type == 3:  # Domain
                domain_length = self.connection.recv(1)[0]
                address = self.connection.recv(domain_length).decode('utf-8')
            elif address_type == 4:  # IPv6
                address = socket.inet_ntop(socket.AF_INET6, self.connection.recv(16))
            else:
                logging.error(f"Unsupported address type: {address_type}")
                return

            port = struct.unpack('!H', self.connection.recv(2))[0]
            logging.debug(f"Target: {address}:{port}")

            # Forward to Burp
            remote = connect_via_burp(address, port)
            bind_address = remote.getsockname()
            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            bport = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, 1, addr, bport)
            self.connection.sendall(reply)
            logging.debug("Sent success reply to client")

            # Relay data
            self.exchange_loop(self.connection, remote, address, port)
        except Exception as e:
            logging.error(f"Error in handle: {e}")
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 5, 0, 1, 0, 0)
            self.connection.sendall(reply)
        finally:
            self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for _ in range(n):
            method = self.connection.recv(1)
            if method:
                methods.append(method[0])
        return methods

    def exchange_loop(self, client, remote, address, port):
        logging.debug(f"Starting data relay for {address}:{port}")
        try:
            last_activity = time.time()
            while True:
                r, w, e = select.select([client, remote], [], [], 60)
                current_time = time.time()
                if current_time - last_activity > 300:
                    logging.debug(f"Idle timeout for {address}:{port}")
                    break

                if client in r:
                    data = client.recv(16384)
                    if len(data) <= 0:
                        logging.debug(f"Client closed connection for {address}:{port}")
                        break
                    logging.debug(f"Client -> Remote ({address}:{port}): {len(data)} bytes")
                    remote.sendall(data)
                    last_activity = current_time
                if remote in r:
                    data = remote.recv(16384)
                    if len(data) <= 0:
                        logging.debug(f"Remote closed connection for {address}:{port}")
                        break
                    logging.debug(f"Remote -> Client ({address}:{port}): {len(data)} bytes")
                    client.sendall(data)
                    last_activity = current_time
        except Exception as e:
            logging.error(f"Error in data relay for {address}:{port}: {e}")
        finally:
            client.close()
            remote.close()

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    max_connections = 100

    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.active_connections = 0
        self.lock = threading.Lock()

    def verify_request(self, request, client_address):
        with self.lock:
            if self.active_connections >= self.max_connections:
                logging.warning("Max connections reached")
                return False
            self.active_connections += 1
        return True

    def close_request(self, request):
        super().close_request(request)
        with self.lock:
            self.active_connections -= 1

if __name__ == '__main__':
    server = ThreadingTCPServer(('0.0.0.0', 9999), SocksProxy)
    print("SOCKS5 proxy server running on 0.0.0.0:9999, forwarding to Burp at 127.0.0.1:8080")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down server...")
        server.shutdown()
        server.server_close()