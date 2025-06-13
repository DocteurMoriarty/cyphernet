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
        self.peers = {}  # {public_key: {"address": address, "username": username, "ws": websocket}}
        self.messages = {}  # {recipient_key: [messages]}
        self.console = Console()
        self.websockets = set()  # Ensemble des connexions WebSocket actives

    async def handle_websocket(self, request):
        """Gère les connexions WebSocket"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.websockets.add(ws)

        try:
            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    if data.get("type") == "register":
                        # Enregistre le WebSocket pour un utilisateur
                        public_key = data.get("public_key")
                        if public_key in self.peers:
                            self.peers[public_key]["ws"] = ws
                            # Envoie la liste des pairs connectés
                            await ws.send_json({
                                "type": "peers_update",
                                "peers": [
                                    {
                                        "key": key,
                                        "username": info["username"],
                                        "status": "online"
                                    }
                                    for key, info in self.peers.items()
                                ]
                            })
                elif msg.type == web.WSMsgType.CLOSE:
                    break
        except Exception as e:
            self.console.print(f"[red]Error in websocket:[/red] {str(e)}")
        finally:
            self.websockets.remove(ws)
            # Marque le pair comme déconnecté
            for key, info in self.peers.items():
                if info.get("ws") == ws:
                    info["ws"] = None
                    # Notifie les autres pairs
                    await self.broadcast_peer_status(key, "offline")
            return ws

    async def broadcast_peer_status(self, peer_key, status):
        """Diffuse le statut d'un pair à tous les WebSockets connectés"""
        message = {
            "type": "peer_status",
            "key": peer_key,
            "status": status
        }
        for ws in self.websockets:
            try:
                await ws.send_json(message)
            except Exception as e:
                self.console.print(f"[red]Error broadcasting status:[/red] {str(e)}")

    async def broadcast_message(self, message):
        """Diffuse un message à tous les WebSockets connectés"""
        for ws in self.websockets:
            try:
                await ws.send_json(message)
            except Exception as e:
                self.console.print(f"[red]Error broadcasting message:[/red] {str(e)}")

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
                "last_seen": datetime.now().isoformat(),
                "ws": None
            }

            # Notifie les autres pairs
            await self.broadcast_peer_status(public_key, "online")

            return web.json_response({
                "status": "connected",
                "peers": [
                    {
                        "key": key,
                        "username": info["username"],
                        "status": "online" if info.get("ws") else "offline"
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
            username = data.get("username")

            if not all([to_key, from_key, message, username]):
                return web.json_response({"error": "Missing required fields"}, status=400)

            # Stocke le message
            if to_key not in self.messages:
                self.messages[to_key] = []
            
            message_data = {
                "from": from_key,
                "message": message,
                "username": username,
                "timestamp": datetime.now().isoformat()
            }
            self.messages[to_key].append(message_data)

            # Envoie le message via WebSocket si le destinataire est connecté
            if to_key in self.peers and self.peers[to_key].get("ws"):
                try:
                    await self.peers[to_key]["ws"].send_json({
                        "type": "new_message",
                        "message": message_data
                    })
                except Exception as e:
                    self.console.print(f"[red]Error sending message via websocket:[/red] {str(e)}")

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
                        "username": info["username"],
                        "status": "online" if info.get("ws") else "offline"
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
        app.router.add_get("/ws", self.handle_websocket)

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