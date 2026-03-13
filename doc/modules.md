# Documentation des modules

## config.py

Fichier de configuration centrale. Contient toutes les constantes du projet.
Aucune logique, uniquement des valeurs.

| Constante | Type | Description |
|-----------|------|-------------|
| `ALLOWED_TARGETS` | list[str] | Cibles autorisées (whitelist) |
| `ALLOWED_PORTS` | list[int] | Ports autorisés au scan |
| `MAX_PORTS_PER_SCAN` | int | Nombre maximum de ports par exécution |
| `SOCKET_TIMEOUT` | float | Délai maximum par connexion (secondes) |
| `REPORTS_DIR` | str | Chemin absolu du dossier des rapports |
| `LOG_LEVEL` | str | Niveau de verbosité des logs |
| `MONGO_URI` | str | URI de connexion MongoDB (variable d'env) |
| `MONGO_DB` | str | Nom de la base de données MongoDB |

---

## scanner_network.py — classe NetworkScanner

Responsabilité : détecter les ports ouverts et récupérer les bannières des services.

| Méthode | Rôle |
|---------|------|
| `scan_ports(host, ports)` | Point d'entrée — retourne la liste des findings |
| `_validate_host(host)` | Vérifie que la cible est autorisée et valide |
| `_validate_ports(ports)` | Filtre les ports invalides ou non autorisés |
| `_probe_port(host, port)` | Tente une connexion TCP — retourne True si ouvert |
| `_grab_banner(host, port)` | Lit la réponse du service (version, type) |
| `_sanitize_banner(data)` | Nettoie les données reçues du réseau |
| `_get_severity(port)` | Retourne HIGH ou MEDIUM selon le port |

### Format d'un finding
```json
{
    "id": "NET_01",
    "service": "port_80",
    "issue": "Port 80 ouvert sur localhost",
    "severity": "MEDIUM",
    "banner": "HTTP/1.0 200 OK Server: SimpleHTTP",
    "timestamp": "2026-03-08T19:31:54+00:00"
}
```

---

## report_manager.py — classe ReportManager

Responsabilité : sauvegarder les rapports en JSON et dans MongoDB.

| Méthode | Rôle |
|---------|------|
| `save_report(host, findings, risk)` | Point d'entrée — sauvegarde JSON + MongoDB |
| `_connect_mongo()` | Tente la connexion MongoDB au démarrage |
| `_build_report(host, findings, risk)` | Construit le dictionnaire du rapport |
| `_safe_path(filename)` | Génère un chemin sécurisé (anti path traversal) |
| `_save_json(report)` | Écrit le rapport en JSON dans reports/ |
| `_save_mongo(report)` | Insère le rapport dans MongoDB |
| `find_by_service(service_name)` | Recherche des audits par nom de service |

### Format du rapport JSON
```json
{
    "meta": {
        "tool": "GuardianPy",
        "version": "2.0.0",
        "target": "localhost",
        "generated_at": "2026-03-08T19:31:59+00:00",
        "total_findings": 1,
        "risk_score": 10,
        "risk_level": "LOW"
    },
    "findings": [...]
}
```

---

## risk_scorer.py — classe RiskScorer

Responsabilité : calculer un score de risque numérique à partir des findings.

| Méthode | Rôle |
|---------|------|
| `compute(findings)` | Point d'entrée — retourne score, level, breakdown |
| `_compute_raw_score(findings)` | Additionne les points selon la sévérité |
| `_normalize(raw_score)` | Ramène le score entre 0 et 100 |
| `_risk_level(score)` | Traduit le score en LOW/MEDIUM/HIGH/CRITICAL |
| `_breakdown(findings)` | Compte les findings par sévérité |

### Tableau des poids
| Sévérité | Points |
|----------|--------|
| CRITICAL | 40 |
| HIGH | 20 |
| MEDIUM | 10 |
| LOW | 5 |

### Tableau des niveaux
| Score | Niveau |
|-------|--------|
| 0-24 | LOW |
| 25-49 | MEDIUM |
| 50-74 | HIGH |
| 75-100 | CRITICAL |

---

## html_reporter.py — classe HtmlReporter

Responsabilité : générer un rapport HTML visuel à partir des findings.

| Méthode | Rôle |
|---------|------|
| `save_report(meta, findings)` | Point d'entrée — génère et sauvegarde le HTML |
| `_escape(text)` | Échappe les caractères HTML (anti-XSS) |
| `_build_rows(findings)` | Génère les lignes du tableau HTML |
| `_build_html(meta, findings)` | Assemble la page HTML complète |

---

## main.py — classe SecurityAudit

Responsabilité : orchestrer toutes les étapes d'un audit.

| Méthode | Rôle |
|---------|------|
| `run()` | Lance les 5 étapes de l'audit |

### Étapes d'exécution
1. Scan des ports → findings
2. Calcul du score de risque
3. Sauvegarde JSON + MongoDB
4. Génération du rapport HTML
5. Alerte CRITICAL si nécessaire

---

## api.py — API Flask

Responsabilité : exposer les données MongoDB via HTTP pour le dashboard.

| Route | Méthode | Description |
|-------|---------|-------------|
| `/api/audits` | GET | Retourne tous les audits |
| `/api/stats` | GET | Retourne les statistiques globales |
