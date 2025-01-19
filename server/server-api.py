#!/usr/bin/env python3
"""
Secure Chat Application - Server Module with REST API
"""
import asyncio
import json
import logging
from aiohttp import web
from typing import Optional

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

    async def get_connected_users(self, request):
        """REST endpoint to get list of connected users with their details"""
        if not self.chat_server.is_running:
            return web.json_response({
                "error": "Server is not running"
            }, status=503)

        users_list = []
        for username, user_id in self.chat_server.users.items():
            client_info = self.chat_server.clients.get(user_id, {})
            users_list.append({
                "username": username,
                "user_id": user_id,
                "connected_since": client_info.get('connected_since', None)
            })

        return web.json_response({
            "users": users_list,
            "total_users": len(users_list)
        })

    async def start(self):
        """Start both the chat server and API server"""
        # Start the chat server
        await self.chat_server.start_server()

        # Setup API routes
        app = web.Application()
        app.router.add_get('/api/status', self.get_server_status)
        app.router.add_get('/api/users', self.get_connected_users)

        # Add CORS middleware
        app.router.add_options('/api/users', self.handle_options)
        app.middlewares.append(self.cors_middleware)

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

    @staticmethod
    async def handle_options(request):
        """Handle CORS preflight requests"""
        return web.Response(headers={
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '3600'
        })

    @staticmethod
    async def cors_middleware(app, handler):
        """CORS middleware to allow cross-origin requests"""

        async def middleware(request):
            response = await handler(request)
            response.headers['Access-Control-Allow-Origin'] = '*'
            return response

        return middleware


async def main():
    server_api = SecureChatServerAPI(host='0.0.0.0', chat_port=8888, api_port=8000)
    await server_api.start()


if __name__ == '__main__':
    asyncio.run(main())