#!/usr/bin/env python3
import asyncio
import argparse
from rich.console import Console
from rich.panel import Panel
import aiohttp
from aiohttp import web
import json
import time

class CypherNode:
    def __init__(self, port):
        self.console = Console()
        self.port = port
        self.peers = {}  # {peer_key: peer_address}
        self.message_queue = {}  # {recipient_key: [messages]}
        self.app = web.Application()
        self.setup_routes()

    def setup_routes(self):
        """Configure les routes de l'API"""
        self.app.router.add_post('/relay', self.handle_relay)
        self.app.router.add_post('/peer', self.handle_peer)
        self.app.router.add_get('/status', self.handle_status)
        self.app.router.add_get('/messages', self.handle_get_messages)

    async def handle_relay(self, request):
        """Gère le relai des messages chiffrés"""
        try:
            data = await request.json()
            sender_key = data.get('sender_key')
            recipient_key = data.get('recipient_key')
            encrypted_message = data.get('encrypted_message')
            timestamp = data.get('timestamp')

            if not all([sender_key, recipient_key, encrypted_message, timestamp]):
                return web.json_response({"error": "missing fields"}, status=400)

            # Stocke le message pour le destinataire
            if recipient_key not in self.message_queue:
                self.message_queue[recipient_key] = []
            
            self.message_queue[recipient_key].append({
                "sender_key": sender_key,
                "encrypted_message": encrypted_message,
                "timestamp": timestamp
            })

            self.console.print(f"[green]✓[/green] Message relayé de {sender_key[:8]}... vers {recipient_key[:8]}...")
            return web.json_response({"status": "relayed"})

        except Exception as e:
            self.console.print(f"[red]Error:[/red] {str(e)}")
            return web.json_response({"error": str(e)}, status=400)

    async def handle_peer(self, request):
        """Gère l'ajout de nouveaux pairs"""
        try:
            data = await request.json()
            peer_key = data.get('address')
            if not peer_key:
                return web.json_response({"error": "invalid peer"}, status=400)

            # Stocke l'adresse du pair
            self.peers[peer_key] = request.remote
            self.console.print(f"[green]+[/green] Nouveau pair connecté: {peer_key[:8]}...")
            return web.json_response({"status": "peer added"})

        except Exception as e:
            self.console.print(f"[red]Error:[/red] {str(e)}")
            return web.json_response({"error": str(e)}, status=400)

    async def handle_get_messages(self, request):
        """Gère la récupération des messages pour un pair"""
        try:
            peer_key = request.query.get('key')
            if not peer_key:
                return web.json_response({"error": "missing key"}, status=400)

            # Récupère les messages en attente
            messages = self.message_queue.get(peer_key, [])
            self.message_queue[peer_key] = []  # Vide la file d'attente

            return web.json_response({"messages": messages})

        except Exception as e:
            self.console.print(f"[red]Error:[/red] {str(e)}")
            return web.json_response({"error": str(e)}, status=400)

    async def handle_status(self, request):
        """Retourne le statut du nœud"""
        return web.json_response({
            "status": "running",
            "peers": len(self.peers),
            "port": self.port,
            "message_queue": sum(len(messages) for messages in self.message_queue.values())
        })

    async def start(self):
        """Démarre le serveur"""
        self.console.print(Panel.fit(
            f"[bold green]CypherNode v1.0[/bold green]\n"
            f"[green][+][/green] Listening on port {self.port}\n"
            "[green][+][/green] Ready to relay encrypted messages",
            title="CypherNode",
            border_style="green"
        ))
        
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, 'localhost', self.port)
        await site.start()
        
        # Garde le serveur en vie
        while True:
            await asyncio.sleep(3600)

def main():
    parser = argparse.ArgumentParser(description='CypherNet P2P Node')
    parser.add_argument('--port', type=int, default=9001, help='Port to listen on')
    args = parser.parse_args()

    node = CypherNode(args.port)
    asyncio.run(node.start())

if __name__ == "__main__":
    main()