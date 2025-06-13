#!/usr/bin/env python3
import asyncio
from aiohttp import web
import json
import argparse
from rich.console import Console
from rich.panel import Panel
from datetime import datetime
import aiohttp

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
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    
                    if data["type"] == "register":
                        # Enregistre le WebSocket avec la clé publique
                        public_key = data.get("public_key")
                        if public_key:
                            # Notifie tous les WebSockets de la mise à jour des pairs
                            for ws in self.websockets:
                                try:
                                    await ws.send_json({
                                        "type": "peers_update",
                                        "peers": [
                                            {
                                                "key": key,
                                                "username": info["username"],
                                                "status": info["status"]
                                            }
                                            for key, info in self.peers.items()
                                        ]
                                    })
                                except Exception as e:
                                    print(f"Error sending peers update: {e}")
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
        """Gère l'envoi de messages"""
        try:
            data = await request.json()
            recipient_key = data.get("recipient")
            message = data.get("message")
            username = data.get("username")

            if not all([recipient_key, message, username]):
                return web.Response(status=400, text="Données manquantes")

            # Stocke le message
            if recipient_key not in self.messages:
                self.messages[recipient_key] = []
            
            self.messages[recipient_key].append({
                "from": username,
                "message": message,
                "timestamp": datetime.now().isoformat()
            })

            # Notifie tous les WebSockets connectés
            for ws in self.websockets:
                try:
                    await ws.send_json({
                        "type": "new_message",
                        "message": {
                            "username": username,
                            "message": message,
                            "timestamp": datetime.now().isoformat()
                        }
                    })
                except Exception as e:
                    print(f"Error sending to websocket: {e}")

            return web.Response(status=200, text="Message envoyé")
        except Exception as e:
            print(f"Error handling message: {e}")
            return web.Response(status=500, text=str(e))

    async def handle_messages(self, request):
        """Récupère les messages d'un utilisateur"""
        try:
            data = await request.json()
            public_key = data.get("public_key")

            if not public_key:
                return web.Response(status=400, text="Clé publique manquante")

            messages = self.messages.get(public_key, [])
            return web.json_response(messages)
        except Exception as e:
            print(f"Error getting messages: {e}")
            return web.Response(status=500, text=str(e))

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
        app.router.add_get("/messages", self.handle_messages)
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