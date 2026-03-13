# =============================================================================
# html_reporter.py — Génération du rapport HTML visuel
# =============================================================================
# Ce fichier contient la classe HtmlReporter.
#
# Ce qu'elle fait :
#   1. Prend les métadonnées et findings d'un audit
#   2. Génère une page HTML complète avec style CSS intégré
#   3. Sauvegarde le fichier dans reports/
#
# Sécurité : toutes les données insérées dans le HTML sont échappées
# pour éviter les injections XSS (ex: une bannière contenant du HTML malveillant).
# =============================================================================

import os
import logging
from datetime import datetime, timezone
from config import REPORTS_DIR


class HtmlReporter:
    """Génère un rapport HTML avec niveaux de risque colorés."""

    # Couleurs CSS associées à chaque niveau de sévérité
    SEVERITY_COLORS: dict[str, str] = {
        "CRITICAL": "#7B0000",
        "HIGH":     "#D32F2F",
        "MEDIUM":   "#F57C00",
        "LOW":      "#388E3C",
    }

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        os.makedirs(REPORTS_DIR, exist_ok=True)

    # -------------------------------------------------------------------------
    # ÉCHAPPEMENT HTML (anti-XSS)
    # Convertit les caractères spéciaux HTML en entités sûres.
    # Ex: "<script>" devient "&lt;script&gt;" et ne s'exécute pas.
    # -------------------------------------------------------------------------
    def _escape(self, text: str) -> str:
        return (
            str(text)
            .replace("&",  "&amp;")
            .replace("<",  "&lt;")
            .replace(">",  "&gt;")
            .replace('"',  "&quot;")
            .replace("'",  "&#x27;")
        )

    # -------------------------------------------------------------------------
    # LIGNES DU TABLEAU — génère une ligne HTML par finding
    # -------------------------------------------------------------------------
    def _build_rows(self, findings: list[dict]) -> str:
        rows = ""
        for f in findings:
            color = self.SEVERITY_COLORS.get(f.get("severity", "LOW"), "#388E3C")
            rows += f"""
            <tr>
                <td>{self._escape(f.get('id', ''))}</td>
                <td>{self._escape(f.get('service', ''))}</td>
                <td>{self._escape(f.get('issue', ''))}</td>
                <td style="color:{color}; font-weight:bold;">{self._escape(f.get('severity', ''))}</td>
                <td><code>{self._escape(f.get('banner', 'inconnu'))}</code></td>
                <td>{self._escape(f.get('timestamp', ''))}</td>
            </tr>"""
        return rows

    # -------------------------------------------------------------------------
    # CONSTRUCTION DU HTML COMPLET
    # Utilise une f-string multi-lignes pour assembler la page.
    # Le CSS est intégré directement (pas de dépendance externe).
    # -------------------------------------------------------------------------
    def _build_html(self, meta: dict, findings: list[dict]) -> str:
        score       = meta.get("risk_score", 0)
        level       = meta.get("risk_level", "LOW")
        level_color = self.SEVERITY_COLORS.get(level, "#388E3C")
        rows        = self._build_rows(findings)

        return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>GuardianPy — Rapport d'audit</title>
    <style>
        body   {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #e0e0e0; margin: 0; padding: 20px; }}
        h1     {{ color: #00d4ff; }}
        .meta  {{ background: #16213e; padding: 15px; border-radius: 8px; margin-bottom: 20px; }}
        .score {{ font-size: 2em; font-weight: bold; color: {level_color}; }}
        table  {{ width: 100%; border-collapse: collapse; background: #16213e; border-radius: 8px; overflow: hidden; }}
        th     {{ background: #0f3460; padding: 12px; text-align: left; color: #00d4ff; }}
        td     {{ padding: 10px 12px; border-bottom: 1px solid #0f3460; }}
        tr:hover {{ background: #0f3460; }}
        code   {{ background: #0a0a1a; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }}
        .footer {{ margin-top: 20px; color: #555; font-size: 0.8em; }}
    </style>
</head>
<body>
    <h1>GuardianPy — Rapport d'audit</h1>
    <div class="meta">
        <p><strong>Cible :</strong> {self._escape(meta.get('target', ''))}</p>
        <p><strong>Généré le :</strong> {self._escape(meta.get('generated_at', ''))}</p>
        <p><strong>Findings :</strong> {self._escape(str(meta.get('total_findings', 0)))}</p>
        <p><strong>Score de risque :</strong>
           <span class="score">{self._escape(str(score))}/100 — {self._escape(level)}</span>
        </p>
    </div>
    <table>
        <thead>
            <tr>
                <th>ID</th><th>Service</th><th>Problème</th>
                <th>Sévérité</th><th>Bannière</th><th>Timestamp</th>
            </tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>
    <div class="footer">
        GuardianPy v{self._escape(meta.get('version', '2.0.0'))} — rapport généré automatiquement
    </div>
</body>
</html>"""

    # -------------------------------------------------------------------------
    # SAUVEGARDE DU FICHIER HTML
    # Même protection anti path traversal que dans report_manager.py.
    # -------------------------------------------------------------------------
    def save_report(self, meta: dict, findings: list[dict]) -> str:
        date_str  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_name = f"audit_{date_str}.html"
        full_path = os.path.abspath(os.path.join(REPORTS_DIR, safe_name))

        # Vérification que le chemin reste bien dans reports/
        if not full_path.startswith(REPORTS_DIR):
            raise ValueError("Tentative de path traversal détectée !")

        html = self._build_html(meta, findings)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(html)

        self.logger.info(f"Rapport HTML sauvegardé : {full_path}")
        return full_path
