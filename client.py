import socket
import secrets
import hashlib
from Crypto.Cipher import DES

HOST = '127.0.0.1'
PORT = 65432

def generate_keys(shared_secret):
    # Derive two 56-bit keys from the shared secret
    key_material = hashlib.sha256(str(shared_secret).encode()).digest()
    key1 = key_material[:7] + b'\x00'  # Make 8 bytes for DES
    key2 = key_material[7:14] + b'\x00'
    return key1, key2

def decrypt_message(encrypted_msg, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_msg = cipher.decrypt(encrypted_msg)
    return decrypted_msg.strip().decode()

def initialize_session(client):
    p = 23  # A prime number
    g = 5   # A primitive root modulo p
    private_key = secrets.randbelow(p - 1)
    public_key = pow(g, private_key, p)

    client.sendall(str(public_key).encode())

    server_public_key = int(client.recv(1024).decode())
    shared_secret = pow(server_public_key, private_key, p)

    key1, key2 = generate_keys(shared_secret)
    
    print(f"Derived keys - Key1: {key1.hex()}, Key2: {key2.hex()}")
    
    # Receive encrypted session token
    encrypted_token = client.recv(1024)
    session_token = decrypt_message(encrypted_token, key1)
    print(f"Session token received: {session_token}")

    return key1, key2, session_token

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((HOST, PORT))
        key1, key2, session_token = initialize_session(client)

        # Take input from the user
        user_message = input("Enter your message: ")

        # Append the session token to the user's message
        message = f"{user_message};TOKEN:{session_token}"

        print(f"Sending message: {message}")
        client.sendall(message.encode())

        response = client.recv(1024)
        print(f"Received from server: {response.decode()}")

if __name__ == "__main__":
    main()
