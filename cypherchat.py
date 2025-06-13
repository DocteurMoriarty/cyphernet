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
from rich.layout import Layout
from rich.live import Live
from rich.table import Table
from cryptography.hazmat.primitives import serialization
from crypto import CypherCrypto
import time
from cryptography.hazmat.primitives import x25519
from cryptography.fernet import Fernet
import base64

class CypherChat:
    def __init__(self):
        self.console = Console()
        self.username = None
        self.crypto = CypherCrypto()
        self.connected = False
        self.contacts = {}
        self.messages = []
        self.general_messages = []
        self.current_peer = None
        self.session = None
        self.unread_count = 0
        self.current_chat = None
        self.layout = Layout()
        self.load_contacts()

    def load_contacts(self):
        """Charge les contacts depuis le fichier"""
        try:
            if os.path.exists("contacts.json"):
                with open("contacts.json", "r") as f:
                    self.contacts = json.load(f)
        except Exception as e:
            self.console.print(f"[red]Error loading contacts:[/red] {str(e)}")

    def save_contacts(self):
        """Sauvegarde les contacts dans un fichier"""
        try:
            with open("contacts.json", "w") as f:
                json.dump(self.contacts, f)
        except Exception as e:
            self.console.print(f"[red]Error saving contacts:[/red] {str(e)}")

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
        self.console.print("\n[bold]Menu:[/bold]")
        self.console.print("1. Connecter")
        self.console.print("2. Envoyer message")
        self.console.print("3. Voir messages")
        self.console.print("4. Voir contacts")
        self.console.print("5. Voir clés")
        self.console.print("6. Quitter")

    def create_chat_layout(self):
        """Crée la mise en page du chat"""
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        self.layout["main"].split_row(
            Layout(name="contacts", ratio=1),
            Layout(name="chat", ratio=3)
        )

    def update_chat_display(self):
        """Met à jour l'affichage du chat"""
        if not self.current_chat:
            return

        # En-tête
        self.layout["header"].update(Panel(f"Chat avec {self.current_chat[:8]}...", style="bold blue"))

        # Liste des contacts
        contacts_table = Table(show_header=False, box=None)
        contacts_table.add_column("Contacts")
        for key, status in self.contacts.items():
            style = "green" if key == self.current_chat else "white"
            contacts_table.add_row(f"• {key[:8]}...", style=style)
        self.layout["contacts"].update(Panel(contacts_table, title="Contacts"))

        # Zone de chat
        chat_table = Table(show_header=False, box=None)
        chat_table.add_column("Messages")
        for msg in self.messages:
            if msg["sender_key"] == self.current_chat or msg["recipient_key"] == self.current_chat:
                sender = "Vous" if msg["sender_key"] == self.crypto.get_public_key_hex() else msg["sender_key"][:8]
                chat_table.add_row(f"{sender}: {msg['decrypted']}")
        self.layout["chat"].update(Panel(chat_table, title="Messages"))

        # Zone de saisie
        self.layout["footer"].update(Panel("Tapez votre message (ou 'exit' pour quitter)", style="bold yellow"))

    async def connect_to_network(self):
        """Connecte au réseau P2P"""
        if self.session:
            await self.session.close()
            self.session = None

        self.session = aiohttp.ClientSession()
        
        # Demande l'ID et la clé publique si déjà connecté
        if os.path.exists("user_info.json"):
            try:
                with open("user_info.json", "r") as f:
                    user_info = json.load(f)
                    self.username = user_info.get("username")
                    self.crypto.private_key = serialization.load_der_private_key(
                        bytes.fromhex(user_info.get("private_key")),
                        password=None
                    )
                    self.crypto.public_key = self.crypto.private_key.public_key()
                    self.console.print(f"[green]✓[/green] Informations utilisateur chargées")
            except Exception as e:
                self.console.print(f"[red]Error loading user info:[/red] {str(e)}")
        else:
            self.username = Prompt.ask("\nEntrez votre nom d'utilisateur")

        peer_address = Prompt.ask("\nEntrez l'adresse du pair", default="46.202.130.9:9001")
        if ":" not in peer_address:
            peer_address = f"{peer_address}:9001"

        try:
            async with self.session.post(
                f"http://{peer_address}/connect",
                json={
                    "username": self.username,
                    "public_key": self.crypto.get_public_key_hex()
                }
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    self.current_peer = peer_address
                    self.connected = True
                    self.console.print(f"[green]✓[/green] Connecté au réseau")
                    
                    # Sauvegarde les informations utilisateur
                    user_info = {
                        "username": self.username,
                        "private_key": self.crypto.private_key.private_bytes(
                            serialization.Encoding.DER,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()
                        ).hex()
                    }
                    with open("user_info.json", "w") as f:
                        json.dump(user_info, f)
                    
                    # Ajoute les pairs connectés aux contacts
                    for peer in data.get("peers", []):
                        if peer["key"] not in self.contacts:
                            self.contacts[peer["key"]] = "connecté"
                    self.save_contacts()
                else:
                    self.console.print("[red]Error:[/red] Failed to connect to peer")
        except Exception as e:
            self.console.print(f"[red]Error:[/red] {str(e)}")

    async def send_message(self):
        """Envoie un message à un contact"""
        if not self.contacts:
            self.console.print("Aucun contact disponible")
            return

        self.console.print("\nContacts disponibles:")
        for i, (key, status) in enumerate(self.contacts.items(), 1):
            self.console.print(f"{i}. {key[:8]}... ({status})")

        try:
            choice = int(Prompt.ask("\nChoisissez un contact (numéro)"))
            if 1 <= choice <= len(self.contacts):
                recipient_key = list(self.contacts.keys())[choice - 1]
                message = Prompt.ask("\nEntrez votre message")
                
                encrypted = self.crypto.encrypt_message(message, recipient_key)
                async with self.session.post(
                    f"http://{self.current_peer}/message",
                    json={
                        "to": recipient_key,
                        "from": self.crypto.public_key.hex(),
                        "message": encrypted
                    }
                ) as response:
                    if response.status == 200:
                        self.console.print("[green]✓[/green] Message envoyé")
                    else:
                        self.console.print("[red]Error:[/red] Failed to send message")
            else:
                self.console.print("[red]Error:[/red] Choix invalide")
        except ValueError:
            self.console.print("[red]Error:[/red] Entrée invalide")
        except Exception as e:
            self.console.print(f"[red]Error:[/red] {str(e)}")

    async def show_messages(self):
        """Affiche les messages reçus"""
        if not self.messages:
            self.console.print("Aucun message")
            return

        self.console.print("\nMessages:")
        for msg in self.messages:
            self.console.print(f"\nDe: {msg['from'][:8]}...")
            self.console.print(f"Message: {msg['decrypted']}")
            self.console.print(f"Date: {msg['timestamp']}")
            self.console.print("-" * 40)

        self.unread_count = 0

    async def show_contacts(self):
        """Affiche la liste des contacts"""
        self.console.print("\n[bold]Contacts:[/bold]")
        if not self.contacts:
            self.console.print("Aucun contact")
            return
            
        for i, (key, status) in enumerate(self.contacts.items(), 1):
            self.console.print(f"{i}. {key[:8]}... ({status})")

    async def show_keys(self):
        """Affiche les clés de l'utilisateur"""
        self.console.print("\n[bold]My Keys:[/bold]")
        self.console.print(f"Public Key: {self.crypto.get_public_key_hex()}")
        self.console.print(f"Private Key: {self.crypto.private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()}")

    async def main_loop(self):
        """Boucle principale de l'application"""
        self.display_welcome()

        try:
            while True:
                self.display_menu()
                choice = Prompt.ask("\n> ", choices=["1", "2", "3", "4", "5", "6"])

                if choice == "1":
                    await self.connect_to_network()
                elif choice == "2":
                    await self.send_message()
                elif choice == "3":
                    await self.show_messages()
                elif choice == "4":
                    await self.show_contacts()
                elif choice == "5":
                    await self.show_keys()
                elif choice == "6":
                    if self.session:
                        await self.session.close()
                    self.console.print("\n[bold red]Au revoir! 👋[/bold red]")
                    sys.exit(0)
        finally:
            if self.session:
                await self.session.close()

if __name__ == "__main__":
    chat = CypherChat()
    asyncio.run(chat.main_loop()) 