import socket
import os
import json
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

AES_KEY_SIZE = 32
NONCE_SIZE = 16
HMAC_KEY_SIZE = 32
MAX_FILE_SIZE = 1024 * 1024  # 1 MB limit for testing

class Client:
    def __init__(self, host: str = 'localhost', port: int = 5002):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.aes_key = None
        self.hmac_key = None
        self.is_logged_in = False  # Track login status

    def connect(self):
        try:
            self.socket.connect((self.host, self.port))
            
            # Receive server's RSA public key
            rsa_public_key_bytes = self.socket.recv(2480)
            try:
                rsa_public_key = serialization.load_pem_public_key(rsa_public_key_bytes)
                print("RSA public key loaded successfully")
            except Exception as e:
                print(f"Failed to load RSA public key: {e}")
                return False

            # Generate AES and HMAC keys
            self.aes_key = secrets.token_bytes(AES_KEY_SIZE)
            self.hmac_key = secrets.token_bytes(HMAC_KEY_SIZE)
            combined_key = self.aes_key + self.hmac_key
            
            # Encrypt combined AES+HMAC key with server's public RSA key
            encrypted_key = rsa_public_key.encrypt(
                combined_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.socket.send(encrypted_key)
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def send_secure_request(self, request: dict) -> dict:
        try:
            # Convert request to JSON and encrypt with AES-CTR
            plaintext = json.dumps(request).encode('utf-8')
            nonce = secrets.token_bytes(NONCE_SIZE)
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Generate HMAC for integrity
            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(nonce + ciphertext)
            hmac_value = h.finalize()

            # Send message with length prefix
            encrypted_request = nonce + ciphertext + hmac_value
            message_length = len(encrypted_request).to_bytes(4, 'big')
            self.socket.sendall(message_length + encrypted_request)

            # Receive and decrypt response
            response_length = int.from_bytes(self.socket.recv(4), 'big')
            encrypted_response = self.recv_full(response_length)
            nonce = encrypted_response[:NONCE_SIZE]
            ciphertext = encrypted_response[NONCE_SIZE:-32]
            received_hmac = encrypted_response[-32:]

            # Verify and decrypt response
            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(nonce + ciphertext)
            h.verify(received_hmac)
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return json.loads(plaintext.decode('utf-8'))
        except Exception as e:
            print(f"Error sending secure request: {e}")
            return {"status": "failed", "message": str(e)}

    def register(self, username, password):
        return self.send_secure_request({"command": "register", "username": username, "password": password})

    def login(self, username, password):
        response = self.send_secure_request({"command": "login", "username": username, "password": password})
        if response.get("status") == "success":
            self.is_logged_in = True  # Set login status to true
        return response

    def upload_file(self, file_path):
        if not self.is_logged_in:
            print("Please log in first.")
            return

        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                if len(file_data) > MAX_FILE_SIZE:
                    print("Error: File too large to upload.")
                    return

                print(f"Read file data of length {len(file_data)} bytes")

                # Send upload command and wait for server acknowledgment
                command = {"command": "upload"}
                print("Sending upload command to server...")
                self.send_secure_request(command)
                ack_response = self.receive_response()
                print("Received acknowledgment from server:", ack_response)

                if ack_response.get("status") != "ready":
                    print("Error: Server not ready to receive file data.")
                    return

                # Send file data with length prefix
                file_data_length = len(file_data).to_bytes(4, 'big')
                print("Sending file length and data to server...")
                self.socket.sendall(file_data_length + file_data)
                print("File data sent successfully.")

        except Exception as e:
            print(f"Error during file upload: {e}")

    def download_file(self, file_id, save_path):
        try:
            # Send download command to the server
            command = {"command": "download", "file_id": file_id}
            self.send_secure_request(command)

            # Receive file length and encrypted content from the server
            response_length = int.from_bytes(self.socket.recv(4), 'big')
            encrypted_response = self.socket.recv(response_length)
            response_nonce = encrypted_response[:NONCE_SIZE]
            encrypted_file_content = encrypted_response[NONCE_SIZE:]

            # Decrypt the file content
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(response_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_file_content = decryptor.update(encrypted_file_content) + decryptor.finalize()

            # Save the decrypted content to the specified file path
            with open(save_path, 'wb') as f:
                f.write(decrypted_file_content)

            print(f"File with ID {file_id} downloaded and saved to {save_path}")

        except Exception as e:
            print(f"[CLIENT] Error downloading file: {e}")

    def receive_response(self):
        try:
            # Receive response length and encrypted response from server
            response_length = int.from_bytes(self.socket.recv(4), 'big')
            encrypted_response = self.socket.recv(response_length)
            nonce = encrypted_response[:NONCE_SIZE]
            ciphertext = encrypted_response[NONCE_SIZE:-32]
            received_hmac = encrypted_response[-32:]

            # Verify HMAC for integrity
            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(nonce + ciphertext)
            h.verify(received_hmac)

            # Decrypt response
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return json.loads(plaintext.decode('utf-8'))

        except Exception as e:
            print(f"[CLIENT] Error receiving response: {e}")
            return {"status": "failed", "message": str(e)}

    def download_file(self, file_id, save_path):
        try:
            # Ensure the save_path includes a file name, not just a directory
            if os.path.isdir(save_path):
                print("Error: save_path should include a file name, not just a directory.")
                return

            # Send download command to the server
            command = {"command": "download", "file_id": file_id}
            self.send_secure_request(command)

            # Receive file length and encrypted content from the server
            response_length = int.from_bytes(self.socket.recv(4), 'big')
            encrypted_response = self.socket.recv(response_length)
            response_nonce = encrypted_response[:NONCE_SIZE]
            ciphertext = encrypted_response[NONCE_SIZE:-32]
            received_hmac = encrypted_response[-32:]

            # Verify HMAC for integrity
            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(response_nonce + ciphertext)
            h.verify(received_hmac)

            # Decrypt the file content
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(response_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_file_content = decryptor.update(ciphertext) + decryptor.finalize()

            # Save the decrypted content to the specified file path
            with open(save_path, 'wb') as f:
                f.write(decrypted_file_content)

            print(f"File with ID {file_id} downloaded and saved to {save_path}")

        except Exception as e:
            print(f"[CLIENT] Error downloading file: {e}")

    def close(self):
        self.socket.close()

    def recv_full(self, expected_length):
        data = b""
        while len(data) < expected_length:
            part = self.socket.recv(expected_length - len(data))
            if not part:
                raise ConnectionError("Incomplete message received.")
            data += part
        return data

# Client class setup remains the same

if __name__ == "__main__":
    client = Client()
    if client.connect():
        while True:
            action = input("Do you want to (register), (login), or (exit)? ").strip().lower()
            if action == "register":
                username = input("Enter username: ")
                password = input("Enter password: ")
                response = client.register(username, password)
                print(response.get("message"))
                
                if response.get("status") == "success":
                    # After registering, allow for immediate login option
                    print("Registration successful. You can now login.")
                    
            elif action == "login":
                username = input("Enter username: ")
                password = input("Enter password: ")
                response = client.login(username, password)
                print(response.get("message"))

                if response.get("status") == "success":
                    while True:
                        file_action = input("Do you want to (upload) a file, (download) a file, or (logout)? ").strip().lower()
                        if file_action == "upload":
                            file_path = input("Enter the path of the file to upload: ")
                            client.upload_file(file_path)
                        elif file_action == "download":
                            file_id = input("Enter the file ID to download: ")
                            save_path = input("Enter the path to save the file: ")
                            client.download_file(file_id, save_path)
                        elif file_action == "logout":
                            print("Logging out...")
                            client.is_logged_in = False
                            break
                        else:
                            print("Invalid option. Choose upload, download, or logout.")
                else:
                    print("Invalid login details.")
            elif action == "exit":
                print("Exiting client.")
                break
            else:
                print("Invalid choice. Please choose either 'register', 'login', or 'exit'.")
        
        client.close()
