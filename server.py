import socket
import secrets
import hashlib
from Crypto.Cipher import DES
import os

HOST = '127.0.0.1'
PORT = 65432

client_keys = {}  # Stores keys per client: {addr: (key1, key2)}

def generate_keys(shared_secret):
    # Derive two 56-bit keys from the shared secret
    key_material = hashlib.sha256(str(shared_secret).encode()).digest()
    key1 = key_material[:7] + b'\x00'  # Make 8 bytes for DES
    key2 = key_material[7:14] + b'\x00'
    return key1, key2

def encrypt_message(message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = message.ljust(8)
    return cipher.encrypt(padded_message.encode())

def generate_session_token():
    return secrets.token_hex(8)  # Generate a 16-character session token (64-bit)

def handle_client(conn, addr):
    print(f"Connected by {addr}")

    p = 23  # A prime number
    g = 5   # A primitive root modulo p
    private_key = secrets.randbelow(p - 1)
    public_key = pow(g, private_key, p)

    client_public_key = int(conn.recv(1024).decode())
    conn.sendall(str(public_key).encode())

    shared_secret = pow(client_public_key, private_key, p)
    key1, key2 = generate_keys(shared_secret)
    
    client_keys[addr] = (key1, key2)
    
    print(f"Derived keys for {addr} - Key1: {key1.hex()}, Key2: {key2.hex()}")

    # Generate and send encrypted session token
    session_token = generate_session_token()
    encrypted_token = encrypt_message(session_token, key1)
    conn.sendall(encrypted_token)
    
    while True:
        data = conn.recv(1024)
        if not data:
            break
        
        message = data.decode()
        print(f"Received from {addr}: {message}")

        if "TOKEN:" not in message:
            response = "ERROR: No session token"
        else:
            response = "Message received"

        conn.sendall(response.encode())

    conn.close()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen()
        print(f"Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = server.accept()
            handle_client(conn, addr)

if __name__ == "__main__":
   start_server()
