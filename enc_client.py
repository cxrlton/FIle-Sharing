import socket
import os
import json
import secrets
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
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
        self.is_logged_in = False  # Todo: implement sessions

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

    def upload_file(self, file_path, max_downloads=float('inf')):
        if not self.is_logged_in:
            print("Please log in first.")
            return

        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                if len(file_data) > MAX_FILE_SIZE:
                    print("Error: File too large to upload.")
                    return

                print(f"[CLIENT] Original file content before encryption: {file_data}")

                # Encrypt the file data using AES-CTR
                file_nonce = secrets.token_bytes(NONCE_SIZE)
                cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(file_nonce), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_file_data = encryptor.update(file_data) + encryptor.finalize()

                print("[CLIENT] Encrypted file content before sending:", encrypted_file_data)

                # Generate HMAC for integrity
                h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
                h.update(encrypted_file_data)
                auth_tag = h.finalize()
                print("[CLIENT] Generated HMAC:", auth_tag.hex())

                # Send upload command with max_downloads and wait for server acknowledgment
                command = {
                    "command": "upload",
                    "max_downloads": max_downloads
                }
                self.send_secure_request(command)
                ack_response = self.receive_response()
                print("Received acknowledgment from server:", ack_response)

                if ack_response.get("status") != "ready":
                    print("Error: Server not ready to receive file data.")
                    return

                # Send the encrypted file data with nonce and HMAC tag
                file_data_length = len(file_nonce + encrypted_file_data + auth_tag).to_bytes(4, 'big')
                print("Sending encrypted file length and data to server...")
                self.socket.sendall(file_data_length + file_nonce + encrypted_file_data + auth_tag)
                print("Encrypted file data sent successfully.")

        except Exception as e:
            print(f"Error during file upload: {e}")


    def download_file(self, file_id, save_path):
        try:
            if os.path.isdir(save_path) or not os.path.splitext(save_path)[1]:
                print("Error: save_path should include a valid file name, not just a directory.")
                return

            print(f"[CLIENT] Attempting to save file to: {save_path}")

            # Send download command to the server
            command = {"command": "download", "file_id": file_id}
            self.send_secure_request(command)

            # Step 1: Receive acknowledgment as JSON
            ack_response = self.receive_response()
            if ack_response.get("status") != "ready":
                print("Error: Server is not ready to send file data.")
                return

            # Step 2: Receive the file data
            response_length = int.from_bytes(self.socket.recv(4), 'big')
            encrypted_response = self.recv_full(response_length)
            response_nonce = encrypted_response[:NONCE_SIZE]
            file_data = encrypted_response[NONCE_SIZE:-32]  # file_data = nonce + encrypted content
            received_hmac = encrypted_response[-32:]

            # Verify HMAC for integrity
            h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(response_nonce + file_data)
            h.verify(received_hmac)
            print("[CLIENT] HMAC verification successful.")

            # Extract the nonce and encrypted file content from file_data
            file_nonce = file_data[:NONCE_SIZE]
            encrypted_file_data = file_data[NONCE_SIZE:]

            # Decrypt the file content
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(file_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_file_content = decryptor.update(encrypted_file_data) + decryptor.finalize()
            print(f"[CLIENT] Decrypted file content: {decrypted_file_content}")

            # Save the decrypted content to the specified file path
            with open(save_path, 'wb') as f:
                f.write(decrypted_file_content)

            print(f"[CLIENT] File with ID {file_id} downloaded and saved to {save_path}")

        except InvalidSignature:
            print("[CLIENT] HMAC verification failed.")
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
                            max_downloads = input("Enter maximum number of downloads (press Enter for unlimited): ").strip()
                            max_downloads = float('inf') if max_downloads == "" else int(max_downloads)
                            client.upload_file(file_path, max_downloads)
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