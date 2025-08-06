import socketserver
import socket

BLOCKLIST_FILE = "blocked_domains.txt"

def load_blocked_domains():
    with open(BLOCKLIST_FILE, "r") as f:
        return set(line.strip().lower() for line in f if line.strip())

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        domain = self.extract_domain(data)
        blocked_domains = load_blocked_domains()

        if domain in blocked_domains:
            print(f"[⛔ BLOCKED] {domain}")
            # Send fake response (empty IP)
            sock.sendto(self.fake_response(data), self.client_address)
        else:
            # Forward to real DNS server (8.8.8.8)
            forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            forward_sock.sendto(data, ('8.8.8.8', 53))
            resp, _ = forward_sock.recvfrom(512)
            sock.sendto(resp, self.client_address)

    def extract_domain(self, data):
        domain = ''
        length = data[12]
        i = 13
        while length != 0:
            domain += data[i:i+length].decode() + '.'
            i += length + 1
            length = data[i]
        return domain.strip('.').lower()

    def fake_response(self, data):
        response = data[:2] + b'\x81\x83' + data[4:6] + b'\x00\x00\x00\x00\x00\x00' + data[12:]
        return response

if __name__ == "__main__":
    print("🛡️ DNS Filter running on port 53...")
    server = socketserver.UDPServer(('0.0.0.0', 53), DNSHandler)
    server.serve_forever()
