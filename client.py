import socket
import threading
import secrets
import hashlib

HOST = '127.0.0.1'  
PORT = 65432

TERMINATE = threading.Event()
TERMINATE.set()

SS_TOKEN = None

KEY_VERIFICATION = 10
SESSION_TOKEN = 20
CLIENT_ENC_DATA = 30
ENC_AGGR_RESULT = 40
DISCONNECT = 50

def initialize_session(client):
    global SS_TOKEN

    # Diffie-Hellman Parameters
    p = 23  # Use a larger prime number in production
    g = 5
    private_key = secrets.randbelow(p - 1)
    public_key = pow(g, private_key, p)

    # Send public key to server
    client.sendall(str(public_key).encode())

    # Receive server's public key
    server_public_key = int(client.recv(1024).decode())

    # Compute shared secret
    shared_secret = pow(server_public_key, private_key, p)

    # Derive DES keys from shared secret
    secret_hash = hashlib.sha256(str(shared_secret).encode()).digest()
    key1 = secret_hash[:7]  # First 7 bytes
    key2 = secret_hash[7:14]  # Next 7 bytes
    print(f"Derived keys - Key1: {key1.hex()}, Key2: {key2.hex()}")

    # Receive session token after key exchange
    data = client.recv(1024).decode()
    SS_TOKEN = data
    print(f"Session initialized with TOKEN: {SS_TOKEN}")



def test_connection(client):
    """Test if the connection is still alive by sending a ping."""
    try:
        client.sendall("PING".encode())
        response = client.recv(1024).decode()
        return response == "PONG"
    except Exception as e:
        print(f"Connection test failed: {e}")
        return False


def recreate_connection():
    """Recreate the connection and reinitialize the session."""
    global SESSION_TOKEN
    print("Recreating connection...")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    initialize_session(client)  
    return client


def client_communication(message, client):
    """Send a message along with the session token."""
    global SS_TOKEN

    # Attach the session token to the message
    message = f"{message};TOKEN:{SESSION_TOKEN}"
    client.sendall(message.encode())
    print(f"Sent to server: {message}")
    
    response = client.recv(1024)
    print(f"Received from server: {response.decode()}")



def starter():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((HOST, PORT))
        initialize_session(client)

        while TERMINATE.is_set():
            message = input("Enter message for server: ")

            if not test_connection(client):
                client.close()
                client = recreate_connection()

            client_communication(message, client)
            if message == "DISCONNECT":
                break


if __name__ == "__main__":
    starter()
