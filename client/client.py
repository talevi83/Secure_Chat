#!/usr/bin/env python3
"""
Secure Chat Application - Client Module

Features:
- Connects to the server
- Menu to "Register" or "Login"
- Registration stores credentials in server DB
- Login performs the RSA handshake + symmetrical encryption
- Interactive messaging
"""

import asyncio
import base64
import json
import logging
import argparse
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

from config_manager import ConfigManager


class SecureChatClient:
    """
    Secure chat client handling connection, encryption, and messaging.
    """

    def __init__(self, config_file: str = 'config.ini'):
        # Initialize configuration
        self.config_manager = ConfigManager(config_file)
        self.host, self.port = self.config_manager.get_server_details()

        # I/O streams
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

        # Authentication and encryption
        self.username: Optional[str] = None
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.symmetric_key: Optional[bytes] = None
        self.fernet: Optional[Fernet] = None

        # Set up logging with configuration
        self.config_manager.setup_logging()
        self.logger = logging.getLogger('SecureChatClient')

    def _serialize_public_key(self) -> bytes:
        """PEM-serialize this client's RSA public key."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def _decrypt_symmetric_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt the server-provided symmetric key with RSA private key."""
        return self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    async def connect(self):
        """Open a connection to the chat server."""
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        self.logger.info(f"Connected to {self.host}:{self.port}")

    async def register(self, username: str, password: str) -> bool:
        """
        1) Receive "ACTION_REQUIRED"
        2) Send {"action":"register","username":..., "password":...}
        3) Receive "REGISTER_OK" or "REGISTER_FAILED"
        Then close the connection.
        """
        # Step 1: read "ACTION_REQUIRED"
        line = await self.reader.readline()
        if not line or line.decode().strip() != "ACTION_REQUIRED":
            self.logger.error("Did not receive ACTION_REQUIRED from server.")
            return False

        # Step 2: send registration info
        reg_data = {
            "action": "register",
            "username": username,
            "password": password
        }
        self.writer.write((json.dumps(reg_data) + "\n").encode())
        await self.writer.drain()

        # Step 3: server responds "REGISTER_OK" or "REGISTER_FAILED"
        resp = await self.reader.readline()
        if not resp:
            self.logger.error("No response from server.")
            return False

        msg = resp.decode().strip()
        if msg == "REGISTER_OK":
            self.logger.info(f"Registration for user '{username}' successful!")
            return True
        else:
            self.logger.error(f"Registration failed: {msg}")
            return False

    async def login(self, username: str, password: str) -> bool:
        """
        1) Receive "ACTION_REQUIRED"
        2) Send {"action":"login","username":..., "password":...}
        3) If "AUTH_FAILED", done. If "AUTH_OK", proceed:
        4) Send public key (multiline PEM)
        5) Receive base64-encoded encrypted key, decode & decrypt
        6) Receive "AUTH_SUCCESS"
        """
        # Step 1: read "ACTION_REQUIRED"
        line = await self.reader.readline()
        if not line or line.decode().strip() != "ACTION_REQUIRED":
            self.logger.error("Did not receive ACTION_REQUIRED from server (login).")
            return False

        # Step 2: send login request
        login_data = {
            "action": "login",
            "username": username,
            "password": password
        }
        self.writer.write((json.dumps(login_data) + "\n").encode())
        await self.writer.drain()

        # Step 3: read "AUTH_FAILED" or "AUTH_OK"
        resp = await self.reader.readline()
        if not resp:
            self.logger.error("No login response from server.")
            return False
        msg = resp.decode().strip()
        if msg == "AUTH_FAILED":
            self.logger.error("Server rejected credentials.")
            return False
        elif msg != "AUTH_OK":
            self.logger.error(f"Unexpected server response: {msg}")
            return False

        # Step 4: Send the public key in PEM format (multiline), plus extra newline
        pem_bytes = self._serialize_public_key()
        self.writer.write(pem_bytes + b"\n")
        await self.writer.drain()

        # Step 5: receive the base64-encoded symmetric key, decode & decrypt
        encoded_key = await self.reader.readline()
        if not encoded_key:
            self.logger.error("No encrypted key from server.")
            return False

        encrypted_symmetric_key = base64.b64decode(encoded_key.strip())
        self.symmetric_key = self._decrypt_symmetric_key(encrypted_symmetric_key)
        self.fernet = Fernet(self.symmetric_key)

        # Step 6: read "AUTH_SUCCESS"
        resp = await self.reader.readline()
        if not resp or resp.decode().strip() != "AUTH_SUCCESS":
            self.logger.error("Did not get AUTH_SUCCESS.")
            return False

        self.logger.info("Login successful!")
        self.username = username
        return True

    async def send_message(self, message: str, to_user: Optional[str] = None):
        """Encrypt + send a message to the server."""
        if not self.writer or not self.fernet:
            raise RuntimeError("Not connected or not logged in")

        try:
            # The 'message' is plain text; we encrypt it with our symmetric key
            encrypted_message = self.fernet.encrypt(message.encode()).decode()
            self.logger.info(f"Original message: {message}")
            self.logger.info(f"Encrypted message: {encrypted_message}")

            # If 'to_user' is set, it means a direct message; otherwise broadcast
            msg_data = {"message": encrypted_message}
            if to_user:
                msg_data["to"] = to_user

            self.logger.info(f"Sending message data to server: {msg_data}")
            # Send JSON
            self.writer.write((json.dumps(msg_data) + "\n").encode())
            await self.writer.drain()

        except Exception as e:
            self.logger.error(f"Error in send_message: {e}")

    async def receive_messages(self):
        """Continuously read & decrypt messages from the server."""
        self.logger.info("Starting receive_messages loop")
        while True:
            try:
                # Read a line from the server
                self.logger.info("Waiting for new message...")
                data = await self.reader.readline()
                if not data:
                    self.logger.info("Received empty data, disconnecting")
                    print("\nDisconnected from server.")
                    break

                # Parse the JSON packet
                self.logger.info(f"Received raw data: {data}")
                packet = json.loads(data.decode().strip())
                self.logger.info(f"Parsed packet: {packet}")

                encrypted_message = packet.get("message", "")
                if not encrypted_message:
                    self.logger.warning("Received packet with no message field")
                    continue

                # Decrypt the message
                try:
                    self.logger.info(f"Attempting to decrypt: {encrypted_message}")
                    decrypted = self.fernet.decrypt(encrypted_message.encode()).decode()
                    self.logger.info(f"Successfully decrypted: {decrypted}")

                    # Get sender information
                    sender_name = packet.get("from", "unknown")

                    # Clear the current input line and print the message
                    print(f"\r[{sender_name}]: {decrypted}")
                    print("Enter message (or 'exit'): ", end="", flush=True)

                except Exception as e:
                    self.logger.error(f"Failed to decrypt message: {e}")
                    self.logger.error(f"Fernet key used: {self.symmetric_key}")
                    continue

            except Exception as e:
                self.logger.error(f"Error in receive_messages: {e}")
                break

        self.logger.info("Message receiving stopped")

    async def interactive_chat(self):
        """
        Read user input in a loop, send messages (until 'exit').
        Meanwhile, a background task receives messages.
        """
        # Start the receive task
        receive_task = asyncio.create_task(self.receive_messages())

        try:
            while True:
                try:
                    # Use asyncio to handle input without blocking message receipt
                    message = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: input("Enter message (or 'exit'): "))

                    if message.lower() == 'exit':
                        break

                    # Handle direct messages starting with @
                    if message.startswith("@"):
                        try:
                            to_user, content = message[1:].split(" ", 1)
                            await self.send_message(content, to_user)
                        except ValueError:
                            print("Format: @username your_message")
                    else:
                        # Broadcast message
                        await self.send_message(message)

                except EOFError:
                    break
                except Exception as e:
                    self.logger.error(f"Error in chat loop: {e}")
                    break

        finally:
            # Clean up
            self.logger.info("Closing chat...")
            receive_task.cancel()
            try:
                await receive_task
            except asyncio.CancelledError:
                pass

            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()

    async def start(self):
        """
        Show a menu: register, login, or quit.
        If login is successful, enter the chat loop.
        """
        while True:
            print("\n=== Secure Chat Client ===")
            print("1) Register new user")
            print("2) Login")
            print("3) Quit")
            choice = input("Choose an option: ").strip()

            if choice == "1":
                # connect and register
                await self.connect()
                username = input("Enter a unique username: ")
                password = input("Enter a password: ")
                success = await self.register(username, password)
                # close after register attempt
                if self.writer:
                    self.writer.close()
                    await self.writer.wait_closed()
                if success:
                    print("You may now login.")
            elif choice == "2":
                # connect and login
                await self.connect()
                username = input("Username: ")
                password = input("Password: ")
                success = await self.login(username, password)
                if success:
                    # proceed to chat
                    await self.interactive_chat()
                    # close after chat
                    if self.writer:
                        self.writer.close()
                        await self.writer.wait_closed()
                else:
                    # close anyway
                    if self.writer:
                        self.writer.close()
                        await self.writer.wait_closed()
            elif choice == "3":
                print("Goodbye!")
                return
            else:
                print("Invalid choice. Please try again.")


async def main():
    parser = argparse.ArgumentParser(description='Secure Chat Client')
    parser.add_argument('--config', default='config.ini', help='Path to configuration file')
    args = parser.parse_args()

    client = SecureChatClient(config_file=args.config)
    await client.start()


if __name__ == '__main__':
    asyncio.run(main())
