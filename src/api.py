# =============================================================================
# api.py — API Flask pour le dashboard GuardianPy
# =============================================================================
# Ce fichier expose les données MongoDB via des routes HTTP (API REST).
# Le dashboard Next.js appelle ces routes pour afficher les audits.
#
# Routes disponibles :
#   GET /api/audits  → retourne tous les audits stockés en MongoDB
#   GET /api/stats   → retourne les statistiques globales
#
# Pour lancer : py src/api.py
# L'API écoute sur http://127.0.0.1:5000
# =============================================================================

import os
import sys
import logging

sys.path.insert(0, os.path.dirname(__file__))

from flask      import Flask, jsonify
from flask_cors import CORS
from pymongo    import MongoClient
from config     import MONGO_URI, MONGO_DB

# Initialisation de l'application Flask
app = Flask(__name__)

# CORS permet au dashboard (port 3000) d'appeler l'API (port 5000)
# Sans ça, le navigateur bloquerait les requêtes cross-origin.
CORS(app)

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# CONNEXION MONGODB — ouvre une nouvelle connexion à chaque requête
# Simple et suffisant pour un usage local.
# -----------------------------------------------------------------------------
def get_collection():
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
    return client[MONGO_DB]["audits"]


# -----------------------------------------------------------------------------
# ROUTE : GET /api/audits
# Retourne la liste complète de tous les audits stockés.
# {"_id": 0} = on exclut l'identifiant interne MongoDB (non sérialisable en JSON)
# -----------------------------------------------------------------------------
@app.route("/api/audits", methods=["GET"])
def get_audits():
    try:
        col    = get_collection()
        audits = list(col.find({}, {"_id": 0}))
        return jsonify(audits)
    except Exception as e:
        logger.error(f"Erreur MongoDB — {type(e).__name__}")
        # On retourne un message générique pour ne pas exposer les détails internes
        return jsonify({"error": "Erreur serveur"}), 500


# -----------------------------------------------------------------------------
# ROUTE : GET /api/stats
# Calcule et retourne les statistiques globales sur tous les audits.
# Utilisé par les cartes de résumé en haut du dashboard.
# -----------------------------------------------------------------------------
@app.route("/api/stats", methods=["GET"])
def get_stats():
    try:
        col    = get_collection()
        audits = list(col.find({}, {"_id": 0}))

        total_audits   = len(audits)
        total_findings = sum(a.get("meta", {}).get("total_findings", 0) for a in audits)

        # Score moyen arrondi à l'entier inférieur
        avg_score = (
            sum(a.get("meta", {}).get("risk_score", 0) for a in audits) // total_audits
            if total_audits > 0 else 0
        )

        # Comptage du nombre de findings par niveau de sévérité
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for audit in audits:
            for finding in audit.get("findings", []):
                sev = finding.get("severity", "LOW")
                if sev in severity_count:
                    severity_count[sev] += 1

        return jsonify({
            "total_audits":       total_audits,
            "total_findings":     total_findings,
            "avg_score":          avg_score,
            "severity_breakdown": severity_count
        })
    except Exception as e:
        logger.error(f"Erreur stats — {type(e).__name__}")
        return jsonify({"error": "Erreur serveur"}), 500


# -----------------------------------------------------------------------------
# LANCEMENT DU SERVEUR
# debug=False en production pour ne pas exposer les traces d'erreur.
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0", port=5000, debug=False)
