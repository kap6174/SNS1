import socket
import threading
import random
import time
import secrets
import hashlib


HOST = '127.0.0.1'  
PORT = 65432

TERMINATE = threading.Event()
TERMINATE.set()

# Session Tokens: {addr: (token, expiry_time, data)}
SESSION_TOKENS = {}

KEY_VERIFICATION = 10
SESSION_TOKEN = 20
CLIENT_ENC_DATA = 30
ENC_AGGR_RESULT = 40
DISCONNECT = 50

def send_keys():
    print("Junaid : Send Keys");

def generate_session_token():
    token = hashlib.sha256(str(random.random()).encode()).hexdigest()
    expiry_time = time.time() + 60  # Token expires in 60 seconds
    return token, expiry_time


def validate_session_token(addr, token):
    if addr not in SESSION_TOKENS:
        return False
    stored_token, expiry_time, data = SESSION_TOKENS[addr]
    return stored_token == token and time.time() <= expiry_time


def handle_client(conn, addr):
    global TERMINATE
    print(f"Connected by {addr}")

    # Diffie-Hellman Parameters
    p = 23  # Use a larger prime number in production
    g = 5
    private_key = secrets.randbelow(p - 1)
    public_key = pow(g, private_key, p)

    # Receive client's public key
    client_public_key = int(conn.recv(1024).decode())

    # Send server's public key to client
    conn.sendall(str(public_key).encode())

    # Compute shared secret
    shared_secret = pow(client_public_key, private_key, p)

    # Derive DES keys from shared secret
    secret_hash = hashlib.sha256(str(shared_secret).encode()).digest()
    key1 = secret_hash[:7]  # First 7 bytes
    key2 = secret_hash[7:14]  # Next 7 bytes
    print(f"Derived keys - Key1: {key1.hex()}, Key2: {key2.hex()}")

    # Continue with session token exchange
    session_token, expiry_time = generate_session_token()
    SESSION_TOKENS[addr] = (session_token, expiry_time, [0])
    conn.sendall(f"{session_token}".encode())

    while True:
        if not validate_session_token(addr, session_token):
            print(f"Session expired for {addr}. Terminating connection.")
            break

        data = conn.recv(1024)
        if not data:
            break

        message = data.decode().strip()
        if message == "DISCONNECT":
            print(f"Client {addr} requested termination.")
            TERMINATE.clear()
            response = "DISCONNECT"
            conn.sendall(response.encode())
            break

        print(f"Received from {addr}: {message}")
        response = "Message received"
        conn.sendall(response.encode())
    
    conn.close()
    del SESSION_TOKENS[addr]
    print(f"Cleaning up session for {addr}")
  

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen()
        server.settimeout(1.0)
        print(f"Server listening on {HOST}:{PORT}")
        while TERMINATE.is_set():
            try:
                conn, addr = server.accept()
                thread = threading.Thread(target=handle_client, args=(conn, addr))
                thread.start()
            except socket.timeout:
                # Timeout reached; check the TERMINATE flag
                continue
            except Exception as e:
                print(f"Error: {e}")
                break
            

        print("Server shutting down...")

if __name__ == "__main__":
    start_server()
