#!/usr/bin/env python3
import os
import sys
import asyncio
import aiohttp
import json
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich import print as rprint
from cryptography.hazmat.primitives import serialization
from crypto import CypherCrypto

class CypherChat:
    def __init__(self):
        self.console = Console()
        self.username = None
        self.crypto = CypherCrypto()
        self.connected = False
        self.contacts = {}
        self.messages = []
        self.current_peer = None
        self.session = None
        self.unread_count = 0

    def display_welcome(self):
        """Affiche l'écran d'accueil"""
        self.console.clear()
        self.console.print(Panel.fit(
            "[bold green]Welcome to CypherNet 🕵️‍♂️💬[/bold green]\n"
            "[green]✓[/green] Chiffrement activé (E2EE)\n"
            f"[green]✓[/green] Identité : @{self.username} (clé: {self.crypto.get_public_key_hex()[:8]}...)",
            title="CypherNet",
            border_style="green"
        ))

    def display_menu(self):
        """Affiche le menu principal"""
        self.console.print("\n[bold]Available commands:[/bold]")
        self.console.print("  1. 📡 Connect to network")
        self.console.print("  2. 💬 Send a message")
        self.console.print(f"  3. 📥 Inbox {f'({self.unread_count})' if self.unread_count > 0 else ''}")
        self.console.print("  4. 👥 Contacts")
        self.console.print("  5. 🔐 My keys")
        self.console.print("  6. 👀 Liste des pairs")
        self.console.print("  7. 🚪 Quit")

    async def connect_to_network(self):
        """Gère la connexion au réseau"""
        peer = Prompt.ask("\nEnter peer address [ip:port]")
        
        # Vérifie si le port est spécifié
        if ':' not in peer:
            peer = f"{peer}:9001"  # Port par défaut
            
        try:
            if self.session:
                await self.session.close()
            
            self.session = aiohttp.ClientSession()
            self.console.print(f"[yellow]Tentative de connexion à {peer}...[/yellow]")
            
            async with self.session.post(f"http://{peer}/peer", 
                json={"address": self.crypto.get_public_key_hex()},
                timeout=10) as response:  # Ajout d'un timeout
                if response.status == 200:
                    self.current_peer = peer
                    self.connected = True
                    self.console.print(f"[green][+][/green] Connected to peer @{peer}")
                    self.console.print("[green][+][/green] Network sync complete")
                else:
                    self.console.print(f"[red]Error:[/red] Failed to connect to peer (status: {response.status})")
                    await self.session.close()
                    self.session = None
        except asyncio.TimeoutError:
            self.console.print("[red]Error:[/red] Connection timeout")
            if self.session:
                await self.session.close()
                self.session = None
        except Exception as e:
            self.console.print(f"[red]Error:[/red] {str(e)}")
            if self.session:
                await self.session.close()
                self.session = None

    async def list_peers(self):
        """Affiche la liste des pairs connectés"""
        if not self.connected or not self.session:
            self.console.print("[red]Error:[/red] Not connected to network")
            return

        try:
            async with self.session.get(f"http://{self.current_peer}/peers") as response:
                if response.status == 200:
                    data = await response.json()
                    self.console.print("\n[bold]Pairs connectés:[/bold]")
                    if not data["peers"]:
                        self.console.print("Aucun pair connecté")
                    else:
                        for peer in data["peers"]:
                            self.console.print(f"- {peer['key'][:8]}... ({peer['address']})")
                            # Ajoute automatiquement aux contacts
                            self.contacts[peer['key']] = "connecté"
                else:
                    self.console.print("[red]Error:[/red] Failed to get peers list")
        except Exception as e:
            self.console.print(f"[red]Error:[/red] {str(e)}")

    async def check_messages(self):
        """Vérifie les nouveaux messages"""
        if not self.connected or not self.session:
            return

        try:
            async with self.session.get(f"http://{self.current_peer}/messages?key={self.crypto.get_public_key_hex()}") as response:
                if response.status == 200:
                    data = await response.json()
                    new_messages = data.get("messages", [])
                    if new_messages:
                        self.messages.extend(new_messages)
                        self.unread_count += len(new_messages)
        except Exception as e:
            self.console.print(f"[red]Error checking messages:[/red] {str(e)}")

    async def show_inbox(self):
        """Affiche la boîte de réception"""
        if not self.messages:
            self.console.print("\n[bold]Inbox:[/bold]")
            self.console.print("Aucun message")
            return

        self.console.print(f"\n[bold]Inbox ({len(self.messages)} messages):[/bold]")
        for msg in self.messages:
            try:
                decrypted = self.crypto.decrypt_message(
                    msg["encrypted_message"], 
                    msg["sender_key"]
                )
                self.console.print(f"🔐 From: {msg['sender_key'][:8]}...")
                self.console.print(f"🕒 {msg['timestamp']}")
                self.console.print(f'"{decrypted}"')
                self.console.print("─" * 40)
            except Exception as e:
                self.console.print(f"[red]Error decrypting message:[/red] {str(e)}")
        
        self.unread_count = 0

    async def show_contacts(self):
        """Affiche la liste des contacts"""
        self.console.print("\n[bold]Contacts:[/bold]")
        for contact, status in self.contacts.items():
            self.console.print(f"- @{contact} ({status})")

    async def show_keys(self):
        """Affiche les clés de l'utilisateur"""
        self.console.print("\n[bold]My Keys:[/bold]")
        self.console.print(f"Public Key: {self.crypto.get_public_key_hex()}")
        self.console.print(f"Private Key: {self.crypto.private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()}")

    async def send_message(self):
        """Gère l'envoi de messages"""
        if not self.connected or not self.session:
            self.console.print("[red]Error:[/red] Not connected to network")
            return

        # Affiche d'abord la liste des contacts
        if self.contacts:
            self.console.print("\n[bold]Contacts disponibles:[/bold]")
            for key, status in self.contacts.items():
                self.console.print(f"- {key[:8]}... ({status})")

        recipient = Prompt.ask("\nTo (username or key)")
        message = Prompt.ask("Message")

        try:
            # Vérifie si le destinataire est dans les contacts
            if recipient in self.contacts:
                recipient_key = recipient
            else:
                # Si c'est un nom d'utilisateur, cherche la clé correspondante
                recipient_key = next((k for k, v in self.contacts.items() if v == recipient), None)
                if not recipient_key:
                    self.console.print("[red]Error:[/red] Destinataire non trouvé")
                    return

            # Crée le paquet de message chiffré
            message_packet = self.crypto.create_message_packet(recipient_key, message)
            
            # Envoie le message au relai
            async with self.session.post(f"http://{self.current_peer}/relay", 
                json=message_packet) as response:
                if response.status == 200:
                    self.console.print("[green]✓[/green] Message chiffré")
                    self.console.print("[green]→[/green] Envoyé via relai")
                else:
                    self.console.print("[red]Error:[/red] Failed to send message")
        except Exception as e:
            self.console.print(f"[red]Error:[/red] {str(e)}")

    async def main_loop(self):
        """Boucle principale de l'application"""
        self.username = Prompt.ask("\nEnter your username")
        self.display_welcome()

        try:
            while True:
                # Vérifie les nouveaux messages
                await self.check_messages()
                
                self.display_menu()
                choice = Prompt.ask("\n> ", choices=["1", "2", "3", "4", "5", "6", "7"])

                if choice == "1":
                    await self.connect_to_network()
                elif choice == "2":
                    await self.send_message()
                elif choice == "3":
                    await self.show_inbox()
                elif choice == "4":
                    await self.show_contacts()
                elif choice == "5":
                    await self.show_keys()
                elif choice == "6":
                    await self.list_peers()
                elif choice == "7":
                    if self.session:
                        await self.session.close()
                    self.console.print("\n[bold red]Goodbye! 👋[/bold red]")
                    sys.exit(0)
        finally:
            if self.session:
                await self.session.close()

if __name__ == "__main__":
    chat = CypherChat()
    asyncio.run(chat.main_loop()) 