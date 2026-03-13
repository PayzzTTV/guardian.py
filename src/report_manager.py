# =============================================================================
# report_manager.py — Sauvegarde des rapports d'audit (JSON + MongoDB)
# =============================================================================
# Ce fichier contient la classe ReportManager.
#
# Ce qu'elle fait :
#   1. Construit un rapport structuré à partir des findings et du score
#   2. Sauvegarde le rapport en JSON dans le dossier reports/
#   3. Insère le rapport dans MongoDB si la connexion est disponible
#
# Si MongoDB est indisponible, le programme continue en mode JSON uniquement.
# =============================================================================

import json
import os
import logging
from datetime import datetime, timezone
from config import REPORTS_DIR, MONGO_URI, MONGO_DB


class ReportManager:
    """Sauvegarde les rapports d'audit en JSON et dans MongoDB."""

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        # Crée le dossier reports/ s'il n'existe pas encore
        os.makedirs(REPORTS_DIR, exist_ok=True)
        self._collection = None
        self._connect_mongo()

    # -------------------------------------------------------------------------
    # CONNEXION MONGODB
    # On essaie de se connecter. Si ça échoue (MongoDB pas lancé, etc.),
    # on continue sans planter — les rapports JSON fonctionneront quand même.
    # -------------------------------------------------------------------------
    def _connect_mongo(self) -> None:
        try:
            from pymongo import MongoClient
            client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
            # "ping" vérifie que MongoDB répond vraiment
            client.admin.command("ping")
            self._collection = client[MONGO_DB]["audits"]
            self.logger.info("Connexion MongoDB établie.")
        except Exception as e:
            self.logger.warning(f"MongoDB indisponible — mode JSON uniquement. ({type(e).__name__})")
            self._collection = None

    # -------------------------------------------------------------------------
    # CHEMIN SÉCURISÉ — protection contre le path traversal
    # Le path traversal est une attaque où un nom de fichier comme
    # "../../etc/passwd" permet d'accéder à des fichiers hors du dossier prévu.
    # os.path.basename() supprime tout ce qui précède le nom du fichier.
    # -------------------------------------------------------------------------
    def _safe_path(self, filename: str) -> str:
        safe_name = os.path.basename(filename)        # supprime les ../ etc.
        full_path = os.path.abspath(os.path.join(REPORTS_DIR, safe_name))

        # Vérification finale : le chemin doit rester dans reports/
        if not full_path.startswith(REPORTS_DIR):
            raise ValueError("Tentative de path traversal détectée !")
        return full_path

    # -------------------------------------------------------------------------
    # CONSTRUCTION DU RAPPORT
    # Assemble les métadonnées et les findings en un seul dictionnaire.
    # -------------------------------------------------------------------------
    def _build_report(self, host: str, findings: list[dict], risk: dict | None = None) -> dict:
        return {
            "meta": {
                "tool":           "GuardianPy",
                "version":        "2.0.0",
                "target":         host,
                "generated_at":   datetime.now(timezone.utc).isoformat(),
                "total_findings": len(findings),
                "risk_score":     risk.get("score", 0)   if risk else 0,
                "risk_level":     risk.get("level", "LOW") if risk else "LOW"
            },
            "findings": findings
        }

    # -------------------------------------------------------------------------
    # SAUVEGARDE JSON
    # Le nom du fichier est horodaté pour éviter les écrasements.
    # Ex: audit_20260308_193000.json
    # -------------------------------------------------------------------------
    def _save_json(self, report: dict) -> str:
        date_str  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        full_path = self._safe_path(f"audit_{date_str}.json")

        # "with open() as f:" garantit que le fichier est fermé même en cas d'erreur
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

        self.logger.info(f"Rapport JSON sauvegardé : {full_path}")
        return full_path

    # -------------------------------------------------------------------------
    # SAUVEGARDE MONGODB
    # On insère uniquement un dict construit en interne (jamais de données
    # externes brutes) pour éviter les injections NoSQL.
    # -------------------------------------------------------------------------
    def _save_mongo(self, report: dict) -> None:
        if self._collection is None:
            return  # MongoDB non disponible, on ignore silencieusement
        try:
            self._collection.insert_one(report)
            self.logger.info("Rapport inséré dans MongoDB.")
        except Exception as e:
            self.logger.error(f"Erreur insertion MongoDB — {type(e).__name__}")

    # -------------------------------------------------------------------------
    # POINT D'ENTRÉE — méthode publique appelée depuis main.py
    # -------------------------------------------------------------------------
    def save_report(self, host: str, findings: list[dict], risk: dict | None = None) -> str:
        report = self._build_report(host, findings, risk)
        path   = self._save_json(report)
        self._save_mongo(report)
        return path

    # -------------------------------------------------------------------------
    # RECHERCHE PAR SERVICE — utilisée par l'API Flask
    # On valide le type et la longueur avant la requête pour éviter
    # les injections NoSQL (ex: {"$gt": ""} à la place d'une string).
    # -------------------------------------------------------------------------
    def find_by_service(self, service_name: str) -> list:
        if self._collection is None:
            self.logger.warning("MongoDB non disponible.")
            return []
        if not isinstance(service_name, str) or len(service_name) > 50:
            raise ValueError(f"Nom de service invalide : {service_name}")
        # {"_id": 0} = ne pas retourner le champ _id de MongoDB
        return list(self._collection.find({"findings.service": service_name}, {"_id": 0}))
