import socket
import hashlib


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = socket.gethostname()


port = 12345

server_socket.bind((host, port))

server_socket.listen(5)

print(f"Server listening on {host}:{port}")

while True:
    client_socket, addr = server_socket.accept()
    print(f"Got connection from {addr}")

    while True:
        data = client_socket.recv(1024)
        if not data:
            break

        hash_obj = hashlib.sha256()
        hash_obj.update(data)
        received_hash = hash_obj.hexdigest()

        client_socket.sendall(received_hash.encode())

    client_socket.close()
    
    
# # Output:
# Server listening on Adityas-MacBook-Air-5.local:12345
# Got connection from ('127.0.0.1', 50561)
