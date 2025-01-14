#!/usr/bin/env python3
"""
Secure Chat Application - Server Module
"""

import asyncio
import base64
import json
import logging
import sqlite3
import uuid
from typing import Dict, Optional

import colorama
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from flask import Flask, current_app, render_template
from server_status_manager import init_app, run_status_app, app
from colorama import init, Fore, Back, Style
from server_status_manager import init_app

app = Flask(__name__)

# We'll keep a reference to our SecureChatServer in a global variable
chat_server = None


class SecureChatServer:
    """
    Main server class for handling secure chat connections
    and user registration/login via SQLite.
    """

    def __init__(self, host: str = 'localhost', port: int = 8888):
        self.host = host
        self.port = port
        self.is_running = False

        # Keep track of connected clients, plus a username→user_id map
        self.clients: Dict[str, Dict] = {}
        self.users: Dict[str, str] = {}

        # Set up logging first
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger('SecureChatServer')

        # Generate a single symmetric key for all clients
        self.symmetric_key = Fernet.generate_key()
        self.logger.info("Generated shared symmetric key for all clients")

        self._setup_database()
        self._server: Optional[asyncio.AbstractServer] = None

    def _setup_database(self):
        """
        Initialize SQLite database for user credentials.
        """
        try:
            self.conn = sqlite3.connect('users.db')
            cursor = self.conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            self.conn.commit()
            self.logger.info("Database initialized successfully")
        except sqlite3.Error as e:
            self.logger.error(f"Database initialization error: {e}")

    def register_user(self, username: str, password: str) -> Optional[str]:
        """
        Insert a new user record into the database (plaintext here for brevity).
        In production, you'd hash the password (e.g. bcrypt/PBKDF2).
        """
        try:
            cursor = self.conn.cursor()
            user_id = str(uuid.uuid4())
            cursor.execute(
                'INSERT INTO users (id, username, password) VALUES (?, ?, ?)',
                (user_id, username, password)
            )
            self.conn.commit()
            self.logger.info(f"User {username} registered successfully")
            return user_id
        except sqlite3.IntegrityError:
            self.logger.warning(f"Username {username} already exists")
            return None

    def authenticate_user(self, username: str, password: str) -> Optional[str]:
        """
        Check if username/password matches a record in the database.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT id FROM users WHERE username = ? AND password = ?',
            (username, password)
        )
        result = cursor.fetchone()
        return result[0] if result else None

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Combined handshake flow:

         1) Server -> "ACTION_REQUIRED"
         2) Client -> { action: "register" | "login", username, password }
         3a) If register: attempt register; send "REGISTER_OK"/"REGISTER_FAILED", close.
         3b) If login:
             - "AUTH_OK"/"AUTH_FAILED"
             - Read multiline public key
             - Encrypt symmetric key & base64 it
             - Send that line + "AUTH_SUCCESS"
             - Enter chat loop
        """
        client_address = writer.get_extra_info('peername')
        self.logger.info(f'New connection from {client_address}')

        try:
            # Step 1: Tell client "ACTION_REQUIRED"
            writer.write(b"ACTION_REQUIRED\n")
            await writer.drain()

            # Step 2: Read JSON with {action, username, password}
            data = await reader.readline()
            if not data:
                writer.close()
                await writer.wait_closed()
                return

            action_info = json.loads(data.decode().strip())
            action = action_info.get("action")
            username = action_info.get("username")
            password = action_info.get("password")

            if action == "register":
                await self._handle_register(username, password, writer)
            elif action == "login":
                await self._handle_login(username, password, reader, writer)
            else:
                writer.write(b"ERROR_UNKNOWN_ACTION\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()

        except Exception as e:
            self.logger.error(f"Error in handle_client: {e}")
            writer.close()
            await writer.wait_closed()

    async def _handle_register(self, username: str, password: str,
                               writer: asyncio.StreamWriter):
        """
        Attempt to register a new user in the DB, then close the connection.
        """
        if not username or not password:
            writer.write(b"REGISTER_FAILED\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        user_id = self.register_user(username, password)
        if user_id:
            writer.write(b"REGISTER_OK\n")
        else:
            writer.write(b"REGISTER_FAILED\n")

        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def _handle_login(self, username: str, password: str,
                            reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Login handshake steps with shared symmetric key
        """
        user_id = self.authenticate_user(username, password)
        if not user_id:
            writer.write(b'AUTH_FAILED\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        # Step: Auth success
        writer.write(b'AUTH_OK\n')
        await writer.drain()

        # Read multiline PEM from the client until "END PUBLIC KEY-----"
        lines = []
        while True:
            line = await reader.readline()
            if not line:
                writer.write(b'PUBLIC_KEY_ERROR\n')
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return
            lines.append(line)
            if b"END PUBLIC KEY-----" in line:
                break

        public_key_pem = b"".join(lines).strip()
        public_key = serialization.load_pem_public_key(public_key_pem)

        # Use the shared symmetric key and encrypt it for this client
        encrypted_symmetric_key = public_key.encrypt(
            self.symmetric_key,  # Use the shared key
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Base64-encode the encrypted key
        encoded_key = base64.b64encode(encrypted_symmetric_key)

        # Store client info
        self.clients[user_id] = {
            'writer': writer,
            'public_key': public_key,
            'username': username
        }
        self.users[username] = user_id

        # Send base64-encoded key
        writer.write(encoded_key + b'\n')
        await writer.drain()

        # Then AUTH_SUCCESS
        writer.write(b'AUTH_SUCCESS\n')
        await writer.drain()

        self.logger.info(f'User {username} authenticated successfully')

        # NEW CODE: Start message receiving loop
        try:
            while True:
                message = await reader.readline()
                if not message:
                    break

                self.logger.info(f"Received message from {username}")
                await self.broadcast_message(message.decode().strip(), user_id)

        except Exception as e:
            self.logger.error(f"Error in message loop for {username}: {e}")
        finally:
            # Clean up when the client disconnects
            if user_id in self.clients:
                del self.clients[user_id]
            if username in self.users:
                del self.users[username]
            writer.close()
            await writer.wait_closed()
            self.logger.info(f"User {username} disconnected")

    async def broadcast_message(self, encrypted_message: str, sender_id: str):
        """
        Broadcast or direct-send the JSON message to target users,
        embedding 'from': <sender_username> so clients see who sent it.
        """
        try:
            message_data = json.loads(encrypted_message)
            target_username = message_data.get('to')
            self.logger.info(f"Broadcasting message from {sender_id}: {message_data}")

            # Insert the sender's username
            sender_info = self.clients.get(sender_id)
            if not sender_info:
                self.logger.error(f"Cannot find sender info for ID {sender_id}")
                return

            sender_name = sender_info['username']
            message_data['from'] = sender_name

            if target_username:
                message_data['is_private'] = True  # Add this flag for private messages
            else:
                message_data['is_private'] = False  # For broadcast messages

            # Re-encode to JSON with the 'from' field
            outgoing = json.dumps(message_data) + "\n"
            self.logger.info(f"Prepared outgoing message: {outgoing}")

            if target_username:
                # Direct message
                target_client_id = self.users.get(target_username)
                if target_client_id:
                    target_client = self.clients.get(target_client_id)
                    if target_client:
                        self.logger.info(f"Sending direct message to {target_username}")
                        writer = target_client['writer']
                        writer.write(outgoing.encode())
                        await writer.drain()
                    else:
                        self.logger.error(f"Target client not found: {target_username}")
                else:
                    self.logger.error(f"Target user not found: {target_username}")
            else:
                # Broadcast to all except sender
                self.logger.info(f"Broadcasting to all users except {sender_name}")
                for client_id, client_info in self.clients.items():
                    if client_id != sender_id:
                        try:
                            writer = client_info['writer']
                            writer.write(outgoing.encode())
                            await writer.drain()
                            self.logger.info(f"Broadcast message sent to client {client_info['username']}")
                        except Exception as e:
                            self.logger.error(f"Error sending to client {client_id}: {e}")

        except json.JSONDecodeError as e:
            self.logger.error(f"JSON decode error in broadcast: {e}")
        except Exception as e:
            self.logger.error(f'Message broadcast error: {e}')
        print(Fore.RESET)

    async def start_server(self):
        """
        Asynchronously start the chat server.
        """
        self._server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        self.logger.info(f"Server started on {self.host}:{self.port}")
        self.is_running = True


@app.route('/')
def server_status():
    """
    Displays the status of the secure chat server and connected clients.
    """
    if not chat_server:
        return "Server not initialized."

    server_running = chat_server.is_running
    connected_clients = len(chat_server.clients)
    with current_app.app_context():
        return render_template(
            'server_status.html',
            server_running=server_running,
            connected_clients=connected_clients
        )


async def main():
    global chat_server
    chat_server = SecureChatServer(host='0.0.0.0')  # Change this to bind to all interfaces

    # Initialize Flask app with server instance
    init_app(chat_server)

    # Start the Secure Chat server (non-blocking)
    await chat_server.start_server()

    # Run Flask in a separate thread
    import threading
    flask_thread = threading.Thread(target=run_status_app, daemon=True)
    flask_thread.start()

    # Keep the server alive indefinitely
    await chat_server._server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
