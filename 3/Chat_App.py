import socket
from cryptography.fernet import Fernet
import hashlib
import hmac
import base64

def generate_key():
    return base64.urlsafe_b64encode(Fernet.generate_key())

# Encrypt a message using Fernet symmetric key encryption
def encrypt_message(message, key):
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

# Decrypt a message using Fernet symmetric key encryption
def decrypt_message(encrypted_message, key):
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message

# Calculate SHA-512 hash for integrity checking
def calculate_sha512(message):
    sha512 = hashlib.sha512()
    sha512.update(message.encode())
    return sha512.digest()

# Generate HMAC for message authentication
def generate_hmac(message, key):
    h = hmac.new(key, message.encode(), hashlib.sha256)
    return h.digest()

# Server code
def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)

    print("Server listening on port 12345")

    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    # Server's symmetric key for encryption
    key = generate_key()

    while True:
        # Receive encrypted message and HMAC from client
        encrypted_message = client_socket.recv(1024)
        received_hmac = client_socket.recv(32)

        # Decrypt the message using the symmetric key
        decrypted_message = decrypt_message(encrypted_message, key)

        # Verify integrity using SHA-512
        calculated_sha512 = calculate_sha512(decrypted_message)
        if received_hmac != generate_hmac(decrypted_message, key) or received_hmac != calculated_sha512:
            print("Integrity check failed. Possible tampering.")
            break

        print(f"Received from client: {decrypted_message}")

        # Send a response back to the client
        response = "Server response: Message received!"
        encrypted_response = encrypt_message(response, key)
        response_hmac = generate_hmac(response, key)

        client_socket.sendall(encrypted_response)
        client_socket.sendall(response_hmac)

    server_socket.close()

# Client code
def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    # Client's symmetric key for encryption
    key = generate_key()

    while True:
        # Send a message to the server
        message = input("Enter your message: ")
        encrypted_message = encrypt_message(message, key)

        # Calculate SHA-512 hash for integrity
        message_sha512 = calculate_sha512(message)

        # Generate HMAC for message authentication
        message_hmac = generate_hmac(message, key)

        # Send encrypted message and HMAC to the server
        client_socket.sendall(encrypted_message)
        client_socket.sendall(message_hmac)

        # Receive response from the server
        encrypted_response = client_socket.recv(1024)
        received_hmac = client_socket.recv(32)

        # Decrypt the response using the symmetric key
        decrypted_response = decrypt_message(encrypted_response, key)

        # Verify integrity using SHA-512
        calculated_sha512 = calculate_sha512(decrypted_response)
        if received_hmac != generate_hmac(decrypted_response, key) or received_hmac != calculated_sha512:
            print("Integrity check failed. Possible tampering.")
            break

        print(f"Received from server: {decrypted_response}")

    client_socket.close()

if __name__ == "__main__":
    # Start the server in one process
    import multiprocessing
    server_process = multiprocessing.Process(target=server)
    server_process.start()

    # Start the client in another process
    client_process = multiprocessing.Process(target=client)
    client_process.start()

    server_process.join()
    client_process.join()
