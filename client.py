import socket
import secrets
import hashlib
from threading import Thread
from time import sleep
from Crypto.Cipher import DES


SERVER_IP = '127.0.0.1'
SERVER_PORT = 65432


session_token = None
key1 = None
key2 = None
running = True
connected = False
client_socket = None


def generate_keys(shared_secret):
    key_material = hashlib.sha256(str(shared_secret).encode()).digest()
    key1 = key_material[:7] + b'\x00'  
    key2 = key_material[7:14] + b'\x00'
    return key1, key2

def decrypt_message(encrypted_msg, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_msg = cipher.decrypt(encrypted_msg)
    return decrypted_msg.strip().decode()



def initialize_session(client):
    global key1, key2, session_token
    p = 23  
    g = 5   
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



def connect_to_server():
    global connected, client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((SERVER_IP, SERVER_PORT))
    except Exception as e:
        print(f"Connection failed: {e}")
        return None

    initialize_session(client_socket)
    return client_socket


def send_messages():
    global running, connected, client_socket, session_token

    while running:
        try:
            message = input("Enter message (or 'quit' to exit not working for now): ")

            if message.lower() == 'quit':
                running = False
                if client_socket:
                    client_socket.close()
                break

            # Attempt to connect if not connected
            if not connected:
                print("\nAttempting to connect to server...")
                client_socket = connect_to_server()
                connected = True


            # Send the message if connected
            if connected:
                try:
                    full_message = f"{message};TOKEN:{session_token}"
                    client_socket.sendall(full_message.encode())
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    print("Connection lost. Reconnect to send the message.")
                    connected = False
                    if client_socket:
                        client_socket.close()

        except Exception as e:
            print(f"Error: {e}")
            connected = False
            if client_socket:
                client_socket.close()


def receive_messages():
    global running, connected, client_socket

    while running:
        if not connected:
            sleep(1)
            continue
        if connected and client_socket:
            try:
                response = client_socket.recv(1024)
                if response:
                    try:
                        # First try to decrypt if it's an encrypted message
                        if len(response) % 8 == 0:  # Check if it might be encrypted (DES block size)
                            decrypted_response = decrypt_message(response, key1)
                            print(f"\nReceived from server (decrypted): {decrypted_response}")
                            
                            # Handle session expiration
                            if "Session expired" in decrypted_response:
                                connected = False
                                print("Session expired. Reconnecting...")
                                if client_socket:
                                    client_socket.close()
                                continue
                        else:
                            # If not encrypted, decode normally
                            print(f"\nReceived from server: {response.decode()}")
                    except Exception as decode_error:
                        print(f"Error processing response: {decode_error}")
                        # If decryption fails, try normal decode as fallback
                        print(f"\nReceived from server (raw): {response.decode()}")
                else:
                    connected = False
                    if client_socket:
                        client_socket.close()

            except Exception as e:
                if connected:
                    print(f"Error receiving data: {e}")
                connected = False
                if client_socket:
                    client_socket.close()


def main():
    global running

    sender_thread = Thread(target=send_messages)
    receiver_thread = Thread(target=receive_messages)

    sender_thread.start()
    receiver_thread.start()

    sender_thread.join()
    receiver_thread.join()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        running = False
