#!/usr/bin/env python3
import asyncio
from aiohttp import web
import json
import argparse
from rich.console import Console
from rich.panel import Panel
from datetime import datetime

class CypherNode:
    def __init__(self, port=9001):
        self.port = port
        self.peers = {}  # {public_key: {"address": address, "username": username}}
        self.messages = {}  # {recipient_key: [messages]}
        self.console = Console()

    async def handle_connect(self, request):
        """Gère la connexion d'un nouveau pair"""
        try:
            data = await request.json()
            public_key = data.get("public_key")
            username = data.get("username")

            if not public_key or not username:
                return web.json_response({"error": "Missing public_key or username"}, status=400)

            # Ajoute ou met à jour le pair
            self.peers[public_key] = {
                "address": request.remote,
                "username": username,
                "last_seen": datetime.now().isoformat()
            }

            # Retourne la liste des pairs connectés
            return web.json_response({
                "status": "connected",
                "peers": [
                    {
                        "key": key,
                        "address": info["address"],
                        "username": info["username"]
                    }
                    for key, info in self.peers.items()
                ]
            })
        except Exception as e:
            self.console.print(f"[red]Error in handle_connect:[/red] {str(e)}")
            return web.json_response({"error": str(e)}, status=500)

    async def handle_message(self, request):
        """Gère la réception d'un message"""
        try:
            data = await request.json()
            to_key = data.get("to")
            from_key = data.get("from")
            message = data.get("message")

            if not all([to_key, from_key, message]):
                return web.json_response({"error": "Missing required fields"}, status=400)

            # Stocke le message
            if to_key not in self.messages:
                self.messages[to_key] = []
            
            self.messages[to_key].append({
                "from": from_key,
                "message": message,
                "timestamp": datetime.now().isoformat()
            })

            return web.json_response({"status": "message received"})
        except Exception as e:
            self.console.print(f"[red]Error in handle_message:[/red] {str(e)}")
            return web.json_response({"error": str(e)}, status=500)

    async def handle_get_messages(self, request):
        """Gère la récupération des messages"""
        try:
            key = request.query.get("key")
            if not key:
                return web.json_response({"error": "Missing key parameter"}, status=400)

            messages = self.messages.get(key, [])
            # Vide la boîte de réception après lecture
            self.messages[key] = []

            return web.json_response({"messages": messages})
        except Exception as e:
            self.console.print(f"[red]Error in handle_get_messages:[/red] {str(e)}")
            return web.json_response({"error": str(e)}, status=500)

    async def handle_list_peers(self, request):
        """Gère la liste des pairs connectés"""
        try:
            return web.json_response({
                "peers": [
                    {
                        "key": key,
                        "address": info["address"],
                        "username": info["username"]
                    }
                    for key, info in self.peers.items()
                ]
            })
        except Exception as e:
            self.console.print(f"[red]Error in handle_list_peers:[/red] {str(e)}")
            return web.json_response({"error": str(e)}, status=500)

    async def start(self):
        """Démarre le serveur"""
        app = web.Application()
        app.router.add_post("/connect", self.handle_connect)
        app.router.add_post("/message", self.handle_message)
        app.router.add_get("/messages", self.handle_get_messages)
        app.router.add_get("/peers", self.handle_list_peers)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", self.port)
        await site.start()

        self.console.print(Panel(
            f"CypherNode v1.0\n[+] Listening on port {self.port}\n[+] Ready to relay encrypted messages",
            title="CypherNode",
            border_style="blue"
        ))

        try:
            while True:
                await asyncio.sleep(3600)  # Keep the server running
        except KeyboardInterrupt:
            await runner.cleanup()

def main():
    parser = argparse.ArgumentParser(description="CypherNode - Serveur P2P pour CypherNet")
    parser.add_argument("--port", type=int, default=9001, help="Port d'écoute (défaut: 9001)")
    args = parser.parse_args()

    node = CypherNode(args.port)
    asyncio.run(node.start())

if __name__ == "__main__":
    main()