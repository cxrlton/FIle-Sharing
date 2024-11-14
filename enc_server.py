import os
import socket
import json
import threading
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_KEY_SIZE = 32
NONCE_SIZE = 16
HMAC_KEY_SIZE = 32
MAX_FILE_SIZE = 1024 * 1024  # 1 MB for testing
FILE_DIRECTORY = "server_files"

USER_DB = {}

class Server:
    def __init__(self, host='localhost', port=5002):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.aes_key = None
        self.hmac_key = None

        # Generate RSA key pair for server
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

    def handle_client(self, client_socket):
        try:
            # Send RSA public key to client
            rsa_public_key_bytes = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            print("Sending RSA public key to client...")
            client_socket.send(rsa_public_key_bytes)
            print("RSA public key sent successfully")

            # Receive and decrypt AES + HMAC keys from client
            encrypted_key = client_socket.recv(256)
            combined_key = self.rsa_private_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.aes_key, self.hmac_key = combined_key[:AES_KEY_SIZE], combined_key[AES_KEY_SIZE:]
            print("Received and decrypted AES Key: " + self.aes_key.hex())
            print("Received and decrypted HMAC Key: " + self.hmac_key.hex())

            # Keep connection alive and wait for multiple commands
            while True:
                length_prefix = client_socket.recv(4)
                if not length_prefix:
                    print("Client disconnected")
                    break
                message_length = int.from_bytes(length_prefix, 'big')
                encrypted_data = self.recv_full(client_socket, message_length)
                
                request = self.decrypt_and_verify(encrypted_data)
                print(f"Decrypted Request: {request}")
                command = request.get("command").strip()
                print(f"Received Command: {command}")

                if command == "register":
                    response = self.register_user(request["username"], request["password"])
                elif command == "login":
                    response = self.authenticate_user(request["username"], request["password"])
                elif command == "upload":
                    ack_response = {"status": "ready"}
                    self.send_encrypted_response(client_socket, json.dumps(ack_response).encode("utf-8"))
                    response = self.handle_upload(client_socket, request)
                elif command == "download":
                    response = self.handle_download(client_socket, request)
                else:
                    response = {"status": "failed", "message": "Unknown command"}
                
                response_data = json.dumps(response).encode('utf-8')
                self.send_encrypted_response(client_socket, response_data)

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            print(f"Closing client {client_socket}")
            client_socket.close()

    def register_user(self, username, password):
        print(f"Attempting to register user: {username}")
        if username in USER_DB:
            print(f"Username '{username}' already exists in the database")
            return {"status": "failed", "message": "Username already exists"}
        
        # Generate a salt and hash the password
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000, # The number of times hashed. Slows down brute force attacks.
            backend=default_backend()
        )
        password_hash = kdf.derive(password.encode())
        USER_DB[username] = {"salt": salt, "password_hash": password_hash}
        
        print(f"User '{username}' registered successfully")
        return {"status": "success", "message": "User registered successfully"}

    def handle_upload(self, client_socket, request):
        try:
            # Todo: Second time sending ack? Remove?
            # Send "ready" acknowledgment to client
            ack_response = {"status": "ready"}
            self.send_encrypted_response(client_socket, json.dumps(ack_response).encode("utf-8"))

            # Receive the file data length and content
            file_data_length = int.from_bytes(client_socket.recv(4), 'big')
            if file_data_length == 0:
                return {"status": "failed", "message": "No data to upload"}

            # Receive the actual file data based on the length
            # Todo: convert to encrypted response
            file_data = self.recv_full(client_socket, file_data_length)
            if len(file_data) != file_data_length:
                return {"status": "failed", "message": "Incomplete file data received"}
            # for debugging purposes
            # print("File data: " + str(file_data))

            # Server-side Encrypt file data before saving
            # todo: this is encrypted by the key given by the client. It should be a key generated by the server.
            file_nonce = secrets.token_bytes(NONCE_SIZE)
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(file_nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_file_data = encryptor.update(file_data) + encryptor.finalize()

            # Save nonce with encrypted data to ensure proper decryption on retrieval
            file_id = secrets.token_hex(24)
            file_path = os.path.join(FILE_DIRECTORY, file_id)
            os.makedirs(FILE_DIRECTORY, exist_ok=True)
            # todo: change to store in a better, retreivable way
            with open(file_path, 'wb') as f:
                f.write(file_nonce + encrypted_file_data)

            # Print the encrypted content for verification
            with open(file_path, 'rb') as f:
                encrypted_content = f.read()
                print(f"Encrypted file content stored at {file_path}: {encrypted_content}")

            print(f"Encrypted file received and saved with ID: {file_id}")
            return {"status": "success", "file_id": file_id}
        
        except Exception as e:
            print(f"Error handling file upload: {e}")
            return {"status": "failed", "message": "File upload failed"}

    def handle_download(self, client_socket, request):
        try:
            # Get the file ID from the client's request
            file_id = request.get("file_id")
            if not file_id:
                return {"status": "failed", "message": "File ID not provided"}

            # Locate and open the encrypted file
            file_path = os.path.join(FILE_DIRECTORY, file_id)
            if not os.path.exists(file_path):
                return {"status": "failed", "message": "File not found"}

            with open(file_path, 'rb') as f:
                file_data = f.read()
                file_nonce = file_data[:NONCE_SIZE]
                encrypted_file_content = file_data[NONCE_SIZE:]

            # Decrypt the file content
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(file_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_file_content = decryptor.update(encrypted_file_content) + decryptor.finalize()

            # Is this for encrypted communication? Then can't we use send_encrypted_response or create a similar function?
            # Encrypt the file content before sending it to the client
            response_nonce = secrets.token_bytes(NONCE_SIZE)
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(response_nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_response = response_nonce + (encryptor.update(decrypted_file_content) + encryptor.finalize())

            # Send the encrypted file content to the client
            file_length = len(encrypted_response).to_bytes(4, 'big')
            client_socket.sendall(file_length + encrypted_response)

            print(f"File with ID {file_id} successfully sent to client")
            return {"status": "success", "file_id": file_id}

        except Exception as e:
            print(f"Error handling file download: {e}")
            return {"status": "failed", "message": "File download failed"}
        
    def authenticate_user(self, username, password):
        user_record = USER_DB.get(username)
        if not user_record:
            return {"status": "failed", "message": "User does not exist"}
        
        # Hash the provided password with the stored salt
        salt = user_record["salt"]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        try:
            kdf.verify(password.encode(), user_record["password_hash"])
            return {"status": "success", "message": "Login successful"}
        except Exception:
            return {"status": "failed", "message": "Incorrect password"}

    def send_encrypted_response(self, client_socket, data):
        # Encrypt the response data and send it with HMAC
        response_nonce = secrets.token_bytes(NONCE_SIZE)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(response_nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        # Generate HMAC for integrity
        h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(response_nonce + ciphertext)
        hmac_value = h.finalize()

        # Send length-prefixed encrypted response with HMAC
        print(f"Response Nonce: {response_nonce.hex()}")
        print(f"Ciphertext: {ciphertext.hex()}")
        print(f"HMAC Value: {hmac_value.hex()}")
        encrypted_response = response_nonce + ciphertext + hmac_value
        response_length = len(encrypted_response).to_bytes(4, 'big')
        client_socket.sendall(response_length + encrypted_response)

    def recv_full(self, client_socket, expected_length):
        data = b""
        while len(data) < expected_length:
            part = client_socket.recv(expected_length - len(data))
            if not part:
                raise ConnectionError("Incomplete message received from client.")
            data += part
        return data

    def decrypt_and_verify(self, encrypted_data):
        # Separate the nonce, ciphertext, and HMAC
        nonce = encrypted_data[:NONCE_SIZE]
        ciphertext = encrypted_data[NONCE_SIZE:-32]
        received_hmac = encrypted_data[-32:]

        # Verify HMAC
        h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(nonce + ciphertext)
        h.verify(received_hmac)  # Raises exception if HMAC does not match

        # Decrypt data
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return json.loads(plaintext.decode('utf-8'))

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")

        while True:
            client_socket, address = self.server_socket.accept()
            print(f"Connection from {address}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

if __name__ == "__main__":
    server = Server(port=5002)
    server.start()
