#!/usr/bin/env python3
"""
Secure Chat Application - Server Module with REST API
"""
import asyncio
import json
import logging
from aiohttp import web
from typing import Optional

# Import the SecureChatServer class directly from the local file
from server import SecureChatServer


class SecureChatServerAPI:
    def __init__(self, host: str = 'localhost', chat_port: int = 8888, api_port: int = 8000):
        self.host = host
        self.chat_port = chat_port
        self.api_port = api_port
        self.chat_server = SecureChatServer(host=host, port=chat_port)

        # Setup logging
        self.logger = logging.getLogger('SecureChatServerAPI')

    async def get_server_status(self, request):
        """REST endpoint to get server status"""
        status = {
            "server_running": self.chat_server.is_running,
            "connected_clients": len(self.chat_server.clients),
            "connected_users": list(self.chat_server.users.keys())
        }
        return web.json_response(status)

    async def start(self):
        """Start both the chat server and API server"""
        # Start the chat server
        await self.chat_server.start_server()

        # Setup API routes
        app = web.Application()
        app.router.add_get('/api/status', self.get_server_status)

        # Start API server
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.api_port)
        await site.start()

        self.logger.info(f"Chat server running on {self.host}:{self.chat_port}")
        self.logger.info(f"API server running on {self.host}:{self.api_port}")

        # Keep the servers running
        try:
            await self.chat_server._server.serve_forever()
        finally:
            await runner.cleanup()


async def main():
    server_api = SecureChatServerAPI(host='0.0.0.0', chat_port=8888, api_port=8000)
    await server_api.start()


if __name__ == '__main__':
    asyncio.run(main())