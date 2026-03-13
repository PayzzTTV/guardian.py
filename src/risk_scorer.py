# =============================================================================
# risk_scorer.py — Calcul du score de risque global
# =============================================================================
# Ce fichier contient la classe RiskScorer.
#
# Ce qu'elle fait :
#   1. Additionne les points de chaque finding selon sa sévérité
#   2. Normalise ce total en un score entre 0 et 100
#   3. Détermine un niveau textuel (LOW, MEDIUM, HIGH, CRITICAL)
#   4. Retourne un détail par sévérité (breakdown)
#
# Exemple :
#   2 findings HIGH (20 pts chacun) = 40 pts bruts
#   40 / 200 * 100 = score 20 → niveau LOW
# =============================================================================

import logging


class RiskScorer:
    """Calcule un score de risque global (0-100) à partir des findings."""

    # Points attribués par niveau de sévérité
    # Plus la sévérité est haute, plus l'impact sur le score est grand.
    SEVERITY_WEIGHTS: dict[str, int] = {
        "CRITICAL": 40,
        "HIGH":     20,
        "MEDIUM":   10,
        "LOW":       5,
    }

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    # -------------------------------------------------------------------------
    # SCORE BRUT — somme des points de tous les findings
    # -------------------------------------------------------------------------
    def _compute_raw_score(self, findings: list[dict]) -> int:
        score = 0
        for finding in findings:
            severity = finding.get("severity", "LOW")
            score += self.SEVERITY_WEIGHTS.get(severity, 5)
        return score

    # -------------------------------------------------------------------------
    # NORMALISATION — ramène le score brut entre 0 et 100
    # max_score = 200 correspond à 10 findings HIGH (cas extrême réaliste).
    # min() garantit qu'on ne dépasse jamais 100.
    # -------------------------------------------------------------------------
    def _normalize(self, raw_score: int, max_score: int = 200) -> int:
        if max_score == 0:
            return 0
        return min(int((raw_score / max_score) * 100), 100)

    # -------------------------------------------------------------------------
    # NIVEAU DE RISQUE — traduit le score numérique en label lisible
    # -------------------------------------------------------------------------
    def _risk_level(self, score: int) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"

    # -------------------------------------------------------------------------
    # DÉTAIL PAR SÉVÉRITÉ — compte le nombre de findings par niveau
    # Ex: {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    # -------------------------------------------------------------------------
    def _breakdown(self, findings: list[dict]) -> dict:
        breakdown: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            severity = finding.get("severity", "LOW")
            if severity in breakdown:
                breakdown[severity] += 1
        return breakdown

    # -------------------------------------------------------------------------
    # POINT D'ENTRÉE — méthode publique appelée depuis main.py
    # Retourne un dict avec score, level, total et détail.
    # -------------------------------------------------------------------------
    def compute(self, findings: list[dict]) -> dict:
        if not findings:
            self.logger.info("Aucun finding — score = 0.")
            return {"score": 0, "level": "LOW", "total_findings": 0}

        raw   = self._compute_raw_score(findings)
        score = self._normalize(raw)
        level = self._risk_level(score)

        self.logger.info(f"Score de risque : {score}/100 — niveau : {level}")

        return {
            "score":          score,
            "level":          level,
            "total_findings": len(findings),
            "breakdown":      self._breakdown(findings)
        }
