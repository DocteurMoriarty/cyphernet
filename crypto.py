from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
import json
import os
import time

class CypherCrypto:
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
    def get_public_key_bytes(self):
        """Retourne la clé publique en format bytes"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def get_public_key_hex(self):
        """Retourne la clé publique en format hexadécimal"""
        return self.get_public_key_bytes().hex()
    
    def derive_shared_key(self, peer_public_key_bytes):
        """Dérive une clé partagée avec la clé publique du pair"""
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        shared_key = self.private_key.exchange(peer_public_key)
        
        # Utilise HKDF pour dériver une clé de 32 bytes
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'cyphernet_shared_key'
        ).derive(shared_key)
        
        return derived_key
    
    def encrypt_message(self, message, peer_public_key_hex):
        """Chiffre un message pour un pair spécifique"""
        try:
            # Convertit la clé publique hex en bytes
            peer_public_key_bytes = bytes.fromhex(peer_public_key_hex)
            
            # Dérive la clé partagée
            shared_key = self.derive_shared_key(peer_public_key_bytes)
            
            # Crée un objet AESGCM avec la clé partagée
            aesgcm = AESGCM(shared_key)
            
            # Génère un nonce aléatoire
            nonce = os.urandom(12)
            
            # Chiffre le message
            ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
            
            # Combine le nonce et le texte chiffré
            encrypted_data = nonce + ciphertext
            
            # Encode en base64 pour la transmission
            return base64.b64encode(encrypted_data).decode()
            
        except Exception as e:
            raise Exception(f"Erreur de chiffrement: {str(e)}")
    
    def decrypt_message(self, encrypted_message, peer_public_key_hex):
        """Déchiffre un message d'un pair spécifique"""
        try:
            # Convertit la clé publique hex en bytes
            peer_public_key_bytes = bytes.fromhex(peer_public_key_hex)
            
            # Dérive la clé partagée
            shared_key = self.derive_shared_key(peer_public_key_bytes)
            
            # Crée un objet AESGCM avec la clé partagée
            aesgcm = AESGCM(shared_key)
            
            # Décode le message chiffré
            encrypted_data = base64.b64decode(encrypted_message)
            
            # Extrait le nonce (12 premiers bytes)
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # Déchiffre le message
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode()
            
        except Exception as e:
            raise Exception(f"Erreur de déchiffrement: {str(e)}")
    
    def create_message_packet(self, recipient_key, message):
        """Crée un paquet de message complet"""
        encrypted_message = self.encrypt_message(message, recipient_key)
        return {
            "sender_key": self.get_public_key_hex(),
            "recipient_key": recipient_key,
            "encrypted_message": encrypted_message,
            "timestamp": int(time.time())
        } 