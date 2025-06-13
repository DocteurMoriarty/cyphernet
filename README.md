# CypherNet 🕵️‍♂️💬

Un réseau décentralisé avec chiffrement de bout en bout (E2EE) pour une communication sécurisée et anonyme.

## Caractéristiques

- 🔒 Chiffrement de bout en bout (E2EE)
- 🌐 Architecture P2P décentralisée
- 👤 Interface en ligne de commande conviviale
- 🔐 Authentification par clés asymétriques
- 🚀 Relais de messages chiffrés

## Installation

1. Clonez le dépôt :
```bash
git clone https://github.com/votre-username/cyphernet.git
cd cyphernet
```

2. Installez les dépendances :
```bash
pip install -r requirements.txt
```

## Utilisation

### Démarrer un nœud relai

```bash
python cyphernode.py --port 9001
```

### Démarrer le client

```bash
python cypherchat.py
```

## Architecture

```
╔══════════╗            ╔══════════╗            ╔══════════╗
║ Client A ║◀──────────▶║ Node P2P ║◀──────────▶║ Client B ║
╚══════════╝            ╚══════════╝            ╚══════════╝
     ▲                        ▲                       ▲
     │ Génère clés            │ Transfère             │ Génère clés
     │ chiffre le msg         │ msg chiffré           │ déchiffre msg
```

## Sécurité

- Chiffrement : AES-256-GCM avec clé dérivée via X25519 (Diffie-Hellman)
- Authentification : signature Ed25519
- Anonymat : pas de stockage des IP, pseudonymes aléatoires

## Développement

Pour contribuer au projet :

1. Fork le dépôt
2. Créez une branche pour votre fonctionnalité
3. Committez vos changements
4. Poussez vers la branche
5. Créez une Pull Request

## Licence

MIT License - voir le fichier LICENSE pour plus de détails. 