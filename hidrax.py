import socket
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

clients = {} # {username: client_socket}
public_keys = {} # {username: public_key}
groups = {} # {group_name: [usernames]}

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_key(key_bytes):
    return serialization.load_pem_public_key(
        key_bytes,
    )

def encrypt_message(message, public_key):
    return public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(encrypted_message, private_key):
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')

def handle_client(client_socket):
    private_key, public_key = generate_keys()

    username = client_socket.recv(1024).decode('utf-8')
    clients[username] = client_socket
    public_keys[username] = public_key

    # Send public key to client
    client_socket.send(serialize_key(public_key))

    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                break

            decrypted_message = decrypt_message(message, private_key)
            print(f"Received from {username}: {decrypted_message}")

            if decrypted_message.startswith('/create_group'):
                group_name = decrypted_message.split(' ')[1]
                groups[group_name] = [username]
                print(f"Group '{group_name}' created by {username}")
            elif decrypted_message.startswith('/join_group'):
                group_name = decrypted_message.split(' ')[1]
                if group_name in groups:
                    groups[group_name].append(username)
                    print(f"{username} joined group '{group_name}'")
            elif decrypted_message.startswith('/group_message'):
                parts = decrypted_message.split(' ', 2)
                group_name = parts[1]
                msg = parts[2]
                if group_name in groups and username in groups[group_name]:
                    for member in groups[group_name]:
                        if member != username:
                            recipient_public_key = public_keys[member]
                            encrypted_response = encrypt_message(f"[{group_name}] {username}: {msg}", recipient_public_key)
                            clients[member].send(encrypted_response)
            else:
                # Broadcast to other clients (one-to-one)
                for user, sock in clients.items():
                    if user != username:
                        recipient_public_key = public_keys[user]
                        encrypted_response = encrypt_message(f"{username}: {decrypted_message}", recipient_public_key)
                        sock.send(encrypted_response)
        except:
            break

    del clients[username]
    del public_keys[username]
    for group in groups.values():
        if username in group:
            group.remove(username)
    client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 9999))
    server.listen(5)
    print("HidraX server started on port 9999")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()
