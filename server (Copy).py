import socket
import secrets
import hashlib
import select
import time
from datetime import datetime, timedelta
from Crypto.Cipher import DES
from collections import defaultdict
from threading import Lock, Thread

HOST = '127.0.0.1'
PORT = 65432

# Global variables for server state with thread-safe access
client_sessions = {}  # {client_addr: {'token': str, 'expiry': datetime, 'key1': bytes, 'key2': bytes}}
client_data = defaultdict(list)  # Store messages for each client
sessions_lock = Lock()  # Lock for thread-safe access to session data
running = True

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

def check_session_expiry(addr):
    with sessions_lock:
        if addr in client_sessions:
            if datetime.now() > client_sessions[addr]['expiry']:
                # Session expired
                stored_data = client_data[addr]
                response = f"Session expired. Stored messages: {stored_data}"
                try:
                    key1 = client_sessions[addr]['key1']
                    encrypted_response = encrypt_message(response, key1)
                    return True, encrypted_response
                except Exception as e:
                    print(f"Error encrypting expiry message: {e}")
                finally:
                    del client_sessions[addr]
                    del client_data[addr]
    return False, None


def handle_client_connection(client_socket, addr):
    try:
        # DH Key Exchange
        p, g = 23, 5
        private_key = secrets.randbelow(p - 1)
        public_key = pow(g, private_key, p)
        

        # Receive client's public key as bytes
        client_public_key_data = client_socket.recv(1024)
        if not client_public_key_data:
            raise ValueError('No data received for client public key')

        # Decode safely using UTF-8
        client_public_key = (client_public_key_data)
        print('Public Key of Client:', client_public_key)

        # Send server's public key back to the client
        client_socket.sendall(str(public_key))
        print('Sent Public Key to Client:', public_key)
        
        shared_secret = pow(client_public_key, private_key, p)
        key1, key2 = generate_keys(shared_secret)
        
        # Generate and send session token
        session_token = generate_session_token()
        encrypted_token = encrypt_message(session_token, key1)
        client_socket.sendall(encrypted_token)
        
        # Store session information
        with sessions_lock:
            client_sessions[addr] = {
                'token': session_token,
                'expiry': datetime.now() + timedelta(minutes=1),
                'key1': key1,
                'key2': key2
            }
        
        print(f"Session initialized for {addr}")
        
        while True:
            # Check for session expiry
            expired, expiry_msg = check_session_expiry(addr)
            if expired:
                if expiry_msg:
                    client_socket.sendall(expiry_msg)
                break
            
            # Receive and process messages
            try:
                data = client_socket.recv(1024)
                if not data:
                    break
                
                message = data.decode()
                print(f"Received from {addr}: {message}")
                
                if "TOKEN:" not in message:
                    response = "ERROR: No session token"
                    client_socket.sendall(response.encode())
                    continue
                
                msg_parts = message.split(";TOKEN:")
                client_token = msg_parts[1]
                
                with sessions_lock:
                    if addr not in client_sessions:
                        response = "ERROR: No active session"
                        client_socket.sendall(response.encode())
                        break
                    
                    if client_sessions[addr]['token'] != client_token:
                        response = "ERROR: Invalid session token"
                        client_socket.sendall(response.encode())
                        break
                    
                    # Store the client message
                    client_data[addr].append(msg_parts[0])
                    
                    # Send acknowledgment
                    expiry_time = client_sessions[addr]['expiry']
                    response = f"Message stored. Session expires at {expiry_time}"
                    client_socket.sendall(response.encode())
                
            except socket.error:
                break
                
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    
    finally:
        print(f"Client {addr} disconnected")
        with sessions_lock:
            if addr in client_sessions:
                del client_sessions[addr]
            if addr in client_data:
                del client_data[addr]
        client_socket.close()


