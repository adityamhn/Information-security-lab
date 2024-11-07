import socket
import hashlib


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


host = socket.gethostname()


port = 12345


client_socket.connect((host, port))


message = b"Hello, world"
client_socket.sendall(message)


received_hash = client_socket.recv(1024)

print(f"Recieved Hash: {received_hash.decode()}")


hash_obj = hashlib.sha256()
hash_obj.update(message)
local_hash = hash_obj.hexdigest()

print(f"Computed Hash: {local_hash}")


if received_hash.decode() == local_hash:
    print("Data integrity verified. No corruption detected.")
else:
    print("Data corruption detected!")


client_socket.close()

#Output:
# Recieved Hash: 4ae7c3b6ac0beff671efa8cf57386151c06e58ca53a78d83f36107316cec125f
# Computed Hash: 4ae7c3b6ac0beff671efa8cf57386151c06e58ca53a78d83f36107316cec125f
# Data integrity verified. No corruption detected.