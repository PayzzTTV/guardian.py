# =============================================================================
# config.py — Configuration centrale de GuardianPy
# =============================================================================
# Ce fichier contient TOUTES les constantes du projet.
# Règle de sécurité : les secrets (URI MongoDB) viennent des variables
# d'environnement, jamais écrits en dur dans le code.
# =============================================================================

import os

# -----------------------------------------------------------------------------
# CIBLES AUTORISÉES — seules ces adresses peuvent être scannées
# Si tu veux ajouter une cible, ajoute-la ici uniquement.
# -----------------------------------------------------------------------------
ALLOWED_TARGETS: list[str] = ["localhost", "127.0.0.1"]

# -----------------------------------------------------------------------------
# PORTS AUTORISÉS — liste des ports que GuardianPy peut sonder
#   22    = SSH
#   80    = HTTP
#   443   = HTTPS
#   3306  = MySQL
#   5432  = PostgreSQL
#   6379  = Redis
#   27017 = MongoDB
# -----------------------------------------------------------------------------
ALLOWED_PORTS: list[int] = [22, 80, 443, 3306, 5432, 6379, 27017]

# -----------------------------------------------------------------------------
# LIMITES DE SCAN — sécurité pour éviter les abus
# -----------------------------------------------------------------------------
MAX_PORTS_PER_SCAN: int = 20    # Maximum de ports sondés par exécution
SOCKET_TIMEOUT: float  = 1.0   # Délai max par tentative de connexion (secondes)

# -----------------------------------------------------------------------------
# DOSSIER DES RAPPORTS — chemin absolu pour éviter les erreurs de chemin relatif
# -----------------------------------------------------------------------------
REPORTS_DIR: str = os.path.abspath("reports")

# -----------------------------------------------------------------------------
# LOGGING — niveau de verbosité des logs
# Valeurs possibles : DEBUG, INFO, WARNING, ERROR
# Modifiable via : $env:LOG_LEVEL = "DEBUG"
# -----------------------------------------------------------------------------
LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")

# -----------------------------------------------------------------------------
# MONGODB — connexion à la base de données
# Les valeurs par défaut fonctionnent pour une installation locale standard.
# En production, définir les variables d'environnement MONGO_URI et MONGO_DB.
# -----------------------------------------------------------------------------
MONGO_URI: str = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB:  str = os.environ.get("MONGO_DB",  "guardianpy")
