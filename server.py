# server.py
import socket
import json
import threading
import hashlib
import hmac
import secrets
from typing import Dict, Tuple

class Server:
    def __init__(self, host: str = 'localhost', port: int = 5000):
        """Initialize the server with host and port"""
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Temporary in-memory storage for user sessions
        self.active_sessions: Dict[str, str] = {}
        # Temporary in-memory storage for users (replace with database)
        self.users: Dict[str, str] = {}
        
    def generate_session_token(self) -> str:
        """Generate a secure random session token"""
        return secrets.token_urlsafe(32)
    
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Authenticate a user and return success status and session token
        Returns: (success: bool, session_token: str)
        """
        # In production, replace with database lookup and proper password hashing
        if username in self.users and self.users[username] == password:
            session_token = self.generate_session_token()
            self.active_sessions[session_token] = username
            return True, session_token
        return False, ""

    def handle_client(self, client_socket: socket.socket):
        """Handle individual client connections"""
        while True:
            try:
                data = client_socket.recv(1024).decode('utf-8')
                if not data:
                    break
                
                request = json.loads(data)
                command = request.get('command')
                
                if command == 'login':
                    success, token = self.authenticate_user(
                        request['username'], 
                        request['password']
                    )
                    response = {
                        'status': 'success' if success else 'failed',
                        'session_token': token if success else ''
                    }
                    
                elif command == 'register':
                    # Basic registration (replace with proper implementation)
                    username = request['username']
                    if username not in self.users:
                        self.users[username] = request['password']
                        response = {'status': 'success'}
                    else:
                        response = {'status': 'failed', 'message': 'User exists'}
                
                else:
                    response = {'status': 'failed', 'message': 'Invalid command'}
                
                client_socket.send(json.dumps(response).encode('utf-8'))
                
            except Exception as e:
                print(f"Error handling client: {e}")
                break
        
        print(f"Closing client {client_socket}")
        client_socket.close()

    def start(self):
        """Start the server and listen for connections"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")
        
        while True:
            client_socket, address = self.server_socket.accept()
            print(f"Connection from {address}")
            client_thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket,)
            )
            client_thread.start()

def main():
    server = Server()
    server.start()

if __name__ == "__main__":
    main()