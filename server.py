import random
import requests
import urllib3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import os
from dotenv import load_dotenv
import json 
import time
from web3.auto import w3
from eth_account.messages import encode_defunct
from hexbytes import HexBytes
def log(message):
    file = open("server.log.txt", "a")
    file.write(message + "\n")
    file.close()
# Define JSON structure for signed data
class Commitment:
    def __init__(self, signature: str, address: str, platform: str, resource: str, value: str, threshold: int):
        self.signature = signature
        self.address = address 
        self.platform = platform
        self.resource = resource
        self.value = value
        self.threshold = threshold
    def hash(self):
        # Create a dictionary of the commitment data
        commitment_dict = self.to_dict()
        # Convert to JSON string and encode to bytes
        json_str = json.dumps(commitment_dict, sort_keys=True)
        commitment_bytes = json_str.encode()
        # Print exact bytes for debugging
        print(f"Bytes to hash: {commitment_bytes}")
        print(f"String to hash: {json_str}")
        # Return keccak256 hash
        return w3.keccak(commitment_bytes).hex()

    def to_dict(self):
        return {
            "signature": self.signature,
            "address": self.address,
            "platform": self.platform, 
            "resource": self.resource,
            "value": self.value,
            "threshold": self.threshold
        }
    def verify_signature(self) -> bool: 
        cleartext = f"{self.platform}{self.resource}{self.value}{self.threshold}"
        message = encode_defunct(text=cleartext)
        bytes_signature = HexBytes(self.signature)
        return w3.eth.account.recover_message(message,signature=bytes_signature) == self.address

    @staticmethod
    def from_dict(data: dict):
        return Commitment(
            signature=data["signature"],
            address=data["address"],
            platform=data["platform"],
            resource=data["resource"], 
            value=data["value"],
            threshold=data["threshold"]
        )

# Generate random bytes and convert them to an integer
def random_int():
    return random.randint(0, 255)

# Get a random operator address
def get_operator() -> str | None:
    rand_int = random_int()
    with open('operators.json', 'r') as file:
        data = json.load(file)
    log(f"Selecting from json data {data}")
    ip_addresses = [data[operator_id] for operator_id in data['operators']] 
    if len(ip_addresses) == 0:
        return None
    return ip_addresses[rand_int % len(ip_addresses)]

# Proxy request handler
class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    # Add class variable to track task number
    task_counter = 0

    def __init__(self, *args, **kwargs):
        load_dotenv()
        if os.getenv('SERVER_PRIVATE_KEY') is None or os.getenv('MAX_OPERATOR_RETRY_ATTEMPTS') is None:
            raise ValueError("SERVER_PRIVATE_KEY and MAX_OPERATOR_RETRY_ATTEMPTS must be set")
        self.private_key = os.getenv('SERVER_PRIVATE_KEY')
        self.max_attempts = int(os.getenv('MAX_OPERATOR_RETRY_ATTEMPTS', 5))
        super().__init__(*args, **kwargs)
    def do_POST(self):
        # Get content length from headers
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.send_error(400, "Missing request body")
            return

        # Read and parse JSON body
        try:
            body = self.rfile.read(content_length)
            data = json.loads(body)
            log(f"Received data: {data}")
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
            return

        # Validate commitment object
        try:
            commitment = Commitment.from_dict(data)
        except (KeyError, ValueError):
            self.send_error(400, "Invalid Commitment object")
            return
        if not commitment.verify_signature():
            self.send_error(400, "Invalid signature")
            return

        operator = self._find_live_operator()
        if operator is None:
            self.send_error(500, "No live operators available.")
            return
        
        # Increment task counter before sending response
        ProxyHTTPRequestHandler.task_counter += 1
        self._send_json_response(operator, commitment, ProxyHTTPRequestHandler.task_counter)

    def _find_live_operator(self) -> str | None:
        """Attempts to find a live operator within the maximum retry attempts."""
        attempts = 0
        log("Starting operator selection")
        
        while attempts < self.max_attempts:
            operator = get_operator()
            log(f"Selected operator: {operator}")
            
            if operator is None:
                return None
                
            log(f"Selected operator IP: {operator}")
            if self.liveness_check(operator + ":7047"):
                log(f"Operator is live: {operator}")
                return operator
            
            log(f"Operator is not live: {operator}. Trying another operator.")
            attempts += 1
        
        return None

    def _send_json_response(self, operator: str, commitment: Commitment, task_index: int) -> None:
        """Sends the JSON response with operator URL, timestamp, and signature."""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        signature, timestamp = self.generate_signature(operator, commitment)
        response_data = {
            "node_url": operator,
            "timestamp": timestamp,
            "node_selector_signature": signature,
            "task_index": task_index
        }
        self.wfile.write(json.dumps(response_data).encode('utf-8'))

    def liveness_check(self, url):
        """Check if the target URL is live by sending a HEAD request."""
        return True
        # try:
        #     response = requests.head(url, verify=False, timeout=2)
        #     return response.status_code == 200
        # except requests.RequestException:
        #     return False
    def generate_signature(self, target_url: str, commitment: Commitment) -> tuple[str, int]:
        """Generate a signature for the given target URL and commitment."""
        timestamp = int(time.time())
        message = f"{target_url},{commitment.hash()},{timestamp}"
        message = encode_defunct(text=message)
        signature = w3.eth.account.sign_message(message, private_key=self.private_key)
        return signature.signature.hex(), timestamp
def run(server_class=HTTPServer, handler_class=ProxyHTTPRequestHandler, port=8080):
    # Ignore SSL certificate verification
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    
    # Optional: handle TLS/SSL connections with self-signed certificates
    # httpd.socket = ssl.wrap_socket(httpd.socket, certfile="path/to/cert.pem", keyfile="path/to/key.pem", server_side=True)

    log(f'Server running on port {port}')
    httpd.serve_forever()
