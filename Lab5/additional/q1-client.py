import socket
import hashlib

# Client settings
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

def compute_hash(message):
    """Compute the SHA-256 hash of the message."""
    return hashlib.sha256(message.encode()).hexdigest()

def start_client():
    message = "This is a long message that will be sent in parts to demonstrate message reassembly and hashing."
    message_parts = [message[i:i + 20] for i in range(0, len(message), 20)]  # Split the message into parts of size 20

    # Compute the hash of the original message
    original_hash = compute_hash(message)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        
        # Send the message in parts
        for part in message_parts:
            print(f"Sending part: {part}")
            client_socket.sendall(part.encode())

        # Close the sending part of the socket
        client_socket.shutdown(socket.SHUT_WR)

        # Receive the hash from the server
        received_hash = client_socket.recv(1024).decode()
        print("Received hash from server:", received_hash)

    # Verify integrity by comparing the hashes
    if received_hash == original_hash:
        print("Message integrity verified: Hashes match!")
    else:
        print("Message integrity verification failed: Hashes do not match.")

if __name__ == "__main__":
    start_client()
