# client.py
import socket
import json
from typing import Optional, Dict
import hashlib

class Client:
    def __init__(self, host: str = 'localhost', port: int = 5000):
        """Initialize the client with server host and port"""
        self.host = host
        self.port = port
        self.session_token: Optional[str] = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def connect(self):
        """Connect to the server"""
        try:
            self.socket.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def send_request(self, request: Dict) -> Dict:
        """Send a request to the server and return the response"""
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            response = self.socket.recv(1024).decode('utf-8')
            return json.loads(response)
        except Exception as e:
            print(f"Error sending request: {e}")
            return {'status': 'failed', 'message': str(e)}
    
    def login(self, username: str, password: str) -> bool:
        """
        Log in to the server
        Returns: success status (bool)
        """
        request = {
            'command': 'login',
            'username': username,
            'password': password
        }
        
        response = self.send_request(request)
        if response['status'] == 'success':
            self.session_token = response['session_token']
            return True
        return False
    
    def register(self, username: str, password: str) -> bool:
        """
        Register a new user
        Returns: success status (bool)
        """
        request = {
            'command': 'register',
            'username': username,
            'password': password
        }
        
        response = self.send_request(request)
        return response['status'] == 'success'
    
    def close(self):
        """Close the connection to the server"""
        self.socket.close()

# example_usage.py
def main():    
    # Client usage example
    client = Client()
    
    if client.connect():
        print("Select operation:\nregister\tlogin")
        operation = input()
        if operation == 'register':
            # Register a new user
            print("Username:")
            username = input()
            print("Password:")
            password = input()
            if client.register(username, password):
                print("Registration successful")
            else:
                print("Registration failed")
        elif operation == 'login':
            # Login
            print("Username:")
            username = input()
            print("Password:")
            password = input()
            if client.login(username, password):
                print("Login successful")
                print(f"Session token: {client.session_token}")
            else:
                print("Login failed")
        else:
            print("invalid operation")
    
    client.close()

if __name__ == "__main__":
    main()