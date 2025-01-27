from collections import defaultdict
from datetime import datetime, timedelta
import socket
import secrets
import hashlib
from threading import Lock, Thread
from Crypto.Cipher import DES
import os

HOST = '127.0.0.1'
PORT = 65432
running = True

client_keys = {}  # Stores keys per client: {addr: (key1, key2)}
client_sessions = {}  # {client_addr: {'token': str, 'expiry': datetime, 'key1': bytes, 'key2': bytes}}
client_data = defaultdict(list)  # Store messages for each client
sessions_lock = Lock()  # Lock for thread-safe access to session data


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
                    # Pad the message to be a multiple of 8 bytes
                    padding_length = 8 - (len(response) % 8)
                    padded_response = response + ' ' * padding_length
                    encrypted_response = encrypt_message(padded_response, key1)
                    return True, encrypted_response
                except Exception as e:
                    print(f"Error encrypting expiry message: {e}")
                finally:
                    del client_sessions[addr]
                    del client_data[addr]
    return False, None

def handle_client_connection(client_socket, addr):
    try:
        print(f"Connected by {addr}")

        # Initial connection setup remains the same...
        p = 23  # A prime number
        g = 5   # A primitive root modulo p
        private_key = secrets.randbelow(p - 1)
        public_key = pow(g, private_key, p)

        # For initial handshake, don't use timeout
        client_socket.settimeout(None)
        client_public_key = int(client_socket.recv(1024).decode())
        client_socket.sendall(str(public_key).encode())

        shared_secret = pow(client_public_key, private_key, p)
        key1, key2 = generate_keys(shared_secret)
        
        client_keys[addr] = (key1, key2)
        
        print(f"Derived keys for {addr} - Key1: {key1.hex()}, Key2: {key2.hex()}")
        print("The shared secret is :", shared_secret)

        # Generate and send encrypted session token
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
        if addr not in client_data:
            client_data[addr] = []
        print(f"Session initialized for {addr}")
        
        # Set timeout for subsequent communications
        client_socket.settimeout(1)
        
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
                    continue  # Don't break on empty data, just continue waiting
                
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
                
            except socket.timeout:
                continue  # On timeout, just continue the loop
            except socket.error as e:
                print(f"Socket error for {addr}: {e}")
                break  # Only break on actual socket errors
                
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



def main():
    global running
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    
    print(f"Server listening on {HOST}:{PORT}")
    
    while running:
        try:
            client_socket, addr = server_socket.accept()
            # Create new thread for each client connection
            client_thread = Thread(target=handle_client_connection, args=(client_socket, addr))
            client_thread.daemon = True  # Make thread daemon so it exits when main thread exits
            client_thread.start()
            print(f"New client thread started for {addr}")
            
        except KeyboardInterrupt:
            print("\nShutting down server...")
            break
        except Exception as e:
            print(f"Error accepting connection: {e}")
    
    server_socket.close()

if __name__ == "__main__":
   main()
