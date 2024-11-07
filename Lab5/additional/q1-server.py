import socket
import hashlib

# Server settings
HOST = '127.0.0.1'  # Localhost
PORT = 65432        # Port to listen on

def compute_hash(message):
    """Compute the SHA-256 hash of the message."""
    return hashlib.sha256(message.encode()).hexdigest()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()

        print("Server is listening for incoming connections...")
        conn, addr = server_socket.accept()
        
        with conn:
            print(f"Connected by {addr}")
            full_message = ""

            while True:
                # Receive data from the client in chunks
                data = conn.recv(1024)
                if not data:
                    break
                # Accumulate the message parts
                full_message += data.decode()

            print("Message received from client:", full_message)

            # Compute the hash of the reassembled message
            message_hash = compute_hash(full_message)
            print("Computed hash:", message_hash)

            # Send the computed hash back to the client
            conn.sendall(message_hash.encode())

if __name__ == "__main__":
    start_server()
