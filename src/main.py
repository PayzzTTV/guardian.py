# =============================================================================
# main.py — Point d'entrée de GuardianPy
# =============================================================================
# Ce fichier orchestre toutes les étapes d'un audit :
#   1. Scan des ports (NetworkScanner)
#   2. Calcul du score de risque (RiskScorer)
#   3. Sauvegarde JSON + MongoDB (ReportManager)
#   4. Génération du rapport HTML (HtmlReporter)
#   5. Alerte si des findings CRITICAL sont détectés
#
# Pour lancer : py src/main.py
# Pour simuler sans connexion réelle : $env:DRY_RUN = "true" ; py src/main.py
# =============================================================================

import logging
import os
import sys
from datetime import datetime, timezone

# Permet d'importer les modules du dossier src/ directement
sys.path.insert(0, os.path.dirname(__file__))

from config          import ALLOWED_PORTS, LOG_LEVEL
from scanner_network import NetworkScanner
from report_manager  import ReportManager
from risk_scorer     import RiskScorer
from html_reporter   import HtmlReporter


# -----------------------------------------------------------------------------
# CONFIGURATION DES LOGS
# Définit le format et le niveau des messages de log pour toute l'application.
# -----------------------------------------------------------------------------
def setup_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )


class SecurityAudit:
    """Orchestre le scan réseau et la génération des rapports."""

    def __init__(self, host: str, dry_run: bool = False) -> None:
        self.host         = host
        self.dry_run      = dry_run
        self.logger       = logging.getLogger(__name__)
        # Instanciation de chaque module
        self.scanner      = NetworkScanner()
        self.reporter     = ReportManager()
        self.scorer       = RiskScorer()
        self.html_reporter = HtmlReporter()

    def run(self) -> None:
        self.logger.info(f"Démarrage de l'audit sur : {self.host}")

        # Mode dry-run : on simule sans faire de vraies connexions réseau
        if self.dry_run:
            self.logger.info("Mode dry-run activé — aucune connexion réelle.")
            print("[DRY-RUN] Simulation terminée. Aucun port sondé.")
            return

        # Étape 1 : scan des ports → liste de findings
        findings = self.scanner.scan_ports(self.host, ALLOWED_PORTS)

        if not findings:
            self.logger.info("Aucun port ouvert détecté.")
            print("Audit terminé — aucun port ouvert détecté.")
            return

        # Étape 2 : calcul du score de risque
        risk = self.scorer.compute(findings)

        # Étape 3 : sauvegarde JSON + MongoDB
        report_path = self.reporter.save_report(self.host, findings, risk)

        # Étape 4 : génération du rapport HTML
        # On construit les métadonnées manuellement pour html_reporter
        report_meta = {
            "tool":           "GuardianPy",
            "version":        "2.0.0",
            "target":         self.host,
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "risk_score":     risk["score"],
            "risk_level":     risk["level"]
        }
        html_path = self.html_reporter.save_report(report_meta, findings)

        # Étape 5 : alerte si des ports CRITICAL sont détectés
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        if critical:
            self.logger.warning(f"ALERTE : {len(critical)} finding(s) CRITICAL sur {self.host} !")
            print(f"[ALERTE CRITICAL] {len(critical)} service(s) critique(s) exposé(s) !")

        # Résumé final affiché dans le terminal
        print(f"Audit terminé — {len(findings)} finding(s) — Score : {risk['score']}/100 ({risk['level']})")
        print(f"Rapport JSON  : {report_path}")
        print(f"Rapport HTML  : {html_path}")


# -----------------------------------------------------------------------------
# LANCEMENT DU PROGRAMME
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    setup_logging()

    # DRY_RUN peut être activé via variable d'environnement
    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"

    audit = SecurityAudit(host="localhost", dry_run=dry_run)
    audit.run()
