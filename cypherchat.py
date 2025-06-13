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
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet
import time
import base64
from datetime import datetime

class Crypto:
    def __init__(self):
        # Génère une paire de clés RSA
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def get_public_key_hex(self):
        """Retourne la clé publique en format hexadécimal"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()

    def encrypt_message(self, message: str, recipient_public_key_hex: str) -> str:
        """Chiffre un message avec la clé publique du destinataire"""
        try:
            # Convertit la clé publique hexadécimale en bytes
            recipient_public_key_bytes = bytes.fromhex(recipient_public_key_hex)
            recipient_public_key = serialization.load_pem_public_key(recipient_public_key_bytes)
            
            # Chiffre le message avec la clé publique
            encrypted = recipient_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            raise Exception(f"Erreur de chiffrement: {str(e)}")

    def decrypt_message(self, encrypted_message: str) -> str:
        """Déchiffre un message avec la clé privée"""
        try:
            # Décode le message chiffré
            encrypted = base64.b64decode(encrypted_message)
            
            # Déchiffre avec la clé privée
            decrypted = self.private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode()
        except Exception as e:
            raise Exception(f"Erreur de déchiffrement: {str(e)}")

class CypherChat:
    def __init__(self):
        self.username = None
        self.crypto = Crypto()
        self.contacts = {}  # {key: {"username": username, "status": status}}
        self.messages = []
        self.general_messages = []
        self.unread_count = 0
        self.session = None
        self.ws = None
        self.current_peer = None
        self.console = Console()
        self.load_contacts()

    def load_contacts(self):
        """Charge les contacts depuis le fichier"""
        try:
            if os.path.exists("contacts.json"):
                with open("contacts.json", "r") as f:
                    contacts_data = json.load(f)
                    # Convertit les anciens contacts en nouveau format si nécessaire
                    for key, value in contacts_data.items():
                        if isinstance(value, str):
                            self.contacts[key] = {
                                "username": f"Contact_{key[:8]}",
                                "status": value
                            }
                        else:
                            self.contacts[key] = value
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
        """Affiche le message de bienvenue"""
        self.console.print(Panel(
            f"Welcome to CypherNet 🕵️‍♂️💬\n"
            f"✓ Chiffrement activé (E2EE)\n"
            f"✓ Identité : @{self.username or 'None'} (clé: {self.crypto.get_public_key_hex()[:8]}...)",
            title="CypherNet",
            border_style="blue"
        ))

    def display_menu(self):
        """Affiche le menu principal"""
        self.console.print("\n[bold]Menu:[/bold]")
        self.console.print("1. 📡 Connecter")
        self.console.print("2. 💬 Envoyer message")
        self.console.print("3. 📥 Voir messages")
        self.console.print("4. 👥 Contacts")
        self.console.print("5. 🔐 Voir clés")
        self.console.print("6. 👀 Liste des pairs")
        self.console.print("7. ➕ Ajouter un contact")
        self.console.print("8. �� Quitter")

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

    async def connect_websocket(self):
        """Établit la connexion WebSocket"""
        if self.ws:
            await self.ws.close()
        
        try:
            ws_url = f"ws://{self.current_peer}/ws"
            self.ws = await self.session.ws_connect(ws_url)
            
            # Enregistre le WebSocket
            await self.ws.send_json({
                "type": "register",
                "public_key": self.crypto.get_public_key_hex()
            })
            
            # Démarre la tâche de réception des messages
            asyncio.create_task(self.receive_websocket_messages())
        except Exception as e:
            self.console.print(f"[red]Error connecting to websocket:[/red] {str(e)}")

    async def receive_websocket_messages(self):
        """Reçoit les messages WebSocket"""
        try:
            self.console.print("[yellow]WebSocket:[/yellow] En attente de messages...")
            async for msg in self.ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    self.console.print(f"[yellow]WebSocket:[/yellow] Message reçu: {data['type']}")
                    
                    if data["type"] == "new_message":
                        # Nouveau message reçu
                        message = data["message"]
                        try:
                            # Déchiffre le message
                            decrypted = self.crypto.decrypt_message(message["message"])
                            self.messages.append({
                                "from": message["username"],
                                "message": decrypted,
                                "timestamp": message["timestamp"]
                            })
                            self.unread_count += 1
                            self.console.print(f"\n[bold green]Nouveau message de @{message['username']}[/bold green]")
                            self.console.print(f"💬 {decrypted}")
                            self.console.print("─" * 40)
                        except Exception as e:
                            self.console.print(f"[red]Error decrypting message:[/red] {str(e)}")
                    
                    elif data["type"] == "peers_update":
                        # Mise à jour de la liste des pairs
                        self.console.print("[yellow]WebSocket:[/yellow] Mise à jour des pairs")
                        for peer in data["peers"]:
                            if peer["key"] not in self.contacts:
                                self.contacts[peer["key"]] = {
                                    "username": peer["username"],
                                    "status": peer["status"]
                                }
                                self.save_contacts()
                                self.console.print(f"[green]✓[/green] Nouveau pair ajouté: @{peer['username']}")
                    
                    elif data["type"] == "peer_status":
                        # Mise à jour du statut d'un pair
                        if data["key"] in self.contacts:
                            self.contacts[data["key"]]["status"] = data["status"]
                            self.save_contacts()
                            self.console.print(f"\n[bold]Statut de @{self.contacts[data['key']]['username']} : {data['status']}[/bold]")
                
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    self.console.print("[red]WebSocket:[/red] Connexion fermée")
                    break
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    self.console.print(f"[red]WebSocket:[/red] Erreur: {msg.data}")
                    break
        except Exception as e:
            self.console.print(f"[red]WebSocket:[/red] Erreur de réception: {str(e)}")
        finally:
            if self.ws:
                await self.ws.close()
                self.ws = None
                self.console.print("[yellow]WebSocket:[/yellow] Déconnecté")

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
                            self.contacts[peer["key"]] = {
                                "username": peer["username"],
                                "status": peer["status"]
                            }
                    self.save_contacts()

                    # Connecte au WebSocket
                    await self.connect_websocket()
                else:
                    self.console.print("[red]Error:[/red] Failed to connect to peer")
        except Exception as e:
            self.console.print(f"[red]Error:[/red] {str(e)}")

    async def show_contacts(self):
        """Affiche la liste des contacts"""
        self.console.print("\n[bold]👥 Contacts:[/bold]")
        if not self.contacts:
            self.console.print("Aucun contact")
            return
            
        for i, (key, info) in enumerate(self.contacts.items(), 1):
            username = info.get("username", "Inconnu")
            status = info.get("status", "connecté")
            self.console.print(f"{i}. @{username} ({key[:8]}...) - {status}")

    async def show_keys(self):
        """Affiche les clés de l'utilisateur"""
        self.console.print("\n[bold]🔐 My Keys:[/bold]")
        self.console.print(f"Public Key: {self.crypto.get_public_key_hex()}")
        self.console.print(f"Private Key: {self.crypto.private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()}")

    async def list_peers(self):
        """Affiche la liste des pairs connectés"""
        if not self.session:
            self.console.print("[red]Error:[/red] Non connecté au réseau")
            return

        try:
            async with self.session.get(f"http://{self.current_peer}/peers") as response:
                if response.status == 200:
                    data = await response.json()
                    self.console.print("\n[bold]👀 Pairs connectés:[/bold]")
                    if not data["peers"]:
                        self.console.print("Aucun pair connecté")
                    else:
                        for i, peer in enumerate(data["peers"], 1):
                            self.console.print(f"{i}. @{peer['username']} ({peer['key'][:8]}...)")
                            # Ajoute automatiquement aux contacts
                            if peer["key"] not in self.contacts:
                                self.contacts[peer["key"]] = {
                                    "username": peer["username"],
                                    "status": "connecté"
                                }
                                self.save_contacts()
                else:
                    self.console.print("[red]Error:[/red] Failed to get peers list")
        except Exception as e:
            self.console.print(f"[red]Error:[/red] {str(e)}")

    async def add_contact(self):
        """Ajoute un nouveau contact"""
        self.console.print("\n[bold]➕ Ajouter un contact[/bold]")
        self.console.print("1. Depuis la liste des pairs")
        self.console.print("2. Avec une clé publique")
        
        choice = Prompt.ask("Choisissez une option", choices=["1", "2"])
        
        if choice == "1":
            await self.list_peers()
        elif choice == "2":
            key = Prompt.ask("\nEntrez la clé publique du contact")
            username = Prompt.ask("Entrez le nom d'utilisateur du contact")
            if len(key) == 64:
                self.contacts[key] = {
                    "username": username,
                    "status": "manuel"
                }
                self.save_contacts()
                self.console.print(f"[green]✓[/green] Contact ajouté: @{username} ({key[:8]}...)")
            else:
                self.console.print("[red]Error:[/red] Clé publique invalide")

    async def send_message(self):
        """Envoie un message à un contact"""
        if not self.contacts:
            self.console.print("Aucun contact disponible")
            return

        self.console.print("\n[bold]💬 Contacts disponibles:[/bold]")
        for i, (key, info) in enumerate(self.contacts.items(), 1):
            username = info.get("username", "Inconnu")
            status = info.get("status", "connecté")
            self.console.print(f"{i}. @{username} ({key[:8]}...) - {status}")

        try:
            choice = int(Prompt.ask("\nChoisissez un contact (numéro)"))
            if 1 <= choice <= len(self.contacts):
                recipient_key = list(self.contacts.keys())[choice - 1]
                recipient_info = self.contacts[recipient_key]
                message = Prompt.ask(f"\nMessage pour @{recipient_info['username']}")
                
                # Chiffre le message
                encrypted_message = self.crypto.encrypt_message(message, recipient_key)
                
                # Envoie le message
                async with self.session.post(
                    f"http://{self.current_peer}/message",
                    json={
                        "recipient": recipient_key,
                        "message": encrypted_message,
                        "username": self.username
                    }
                ) as response:
                    if response.status == 200:
                        self.console.print("[green]✓[/green] Message envoyé")
                        # Envoie aussi via WebSocket pour la mise à jour en temps réel
                        if self.ws:
                            await self.ws.send_json({
                                "type": "new_message",
                                "message": {
                                    "username": self.username,
                                    "message": message,
                                    "timestamp": datetime.now().isoformat()
                                }
                            })
                    else:
                        self.console.print("[red]Error:[/red] Échec de l'envoi du message")
            else:
                self.console.print("[red]Error:[/red] Choix invalide")
        except ValueError:
            self.console.print("[red]Error:[/red] Entrée invalide")
        except Exception as e:
            self.console.print(f"[red]Error:[/red] {str(e)}")

    async def show_messages(self):
        """Affiche les messages reçus"""
        try:
            if not self.current_peer:
                self.console.print("[red]Error:[/red] Non connecté au réseau")
                return

            # Récupère les messages du serveur
            async with self.session.get(
                f"http://{self.current_peer}/messages",
                json={"public_key": self.crypto.get_public_key_hex()}
            ) as response:
                if response.status == 200:
                    messages = await response.json()
                    if not messages:
                        self.console.print("\n📥 Messages:")
                        self.console.print("Aucun message")
                        return

                    self.console.print("\n📥 Messages:")
                    for msg in messages:
                        try:
                            # Déchiffre le message
                            decrypted = self.crypto.decrypt_message(msg["message"])
                            self.console.print(f"\n[bold]De:[/bold] @{msg['from']}")
                            self.console.print(f"[bold]Message:[/bold] {decrypted}")
                            self.console.print(f"[bold]Date:[/bold] {msg['timestamp']}")
                            self.console.print("─" * 40)
                        except Exception as e:
                            self.console.print(f"[red]Error decrypting message:[/red] {str(e)}")
                else:
                    self.console.print("[red]Error:[/red] Impossible de récupérer les messages")
        except Exception as e:
            self.console.print(f"[red]Error:[/red] {str(e)}")

    async def main_loop(self):
        """Boucle principale de l'application"""
        self.display_welcome()

        try:
            while True:
                self.display_menu()
                choice = Prompt.ask("\n> ", choices=["1", "2", "3", "4", "5", "6", "7", "8"])

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
                    await self.list_peers()
                elif choice == "7":
                    await self.add_contact()
                elif choice == "8":
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