# Analyse Python — GuardianPy

## Dictionnaires `dict`

| Emplacement | Exemple |
|-------------|---------|
| `risk_scorer.py:25` — `SEVERITY_WEIGHTS` | `{"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}` |
| `risk_scorer.py:72` — `breakdown` | `{"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0}` |
| `scanner_network.py:141` — chaque finding | `{"id": "NET_01", "service": "port_27017", "severity": "HIGH", ...}` |
| `report_manager.py:68` — rapport complet | `{"meta": {...}, "findings": [...]}` |

---

## Listes `list`

| Emplacement | Description |
|-------------|-------------|
| `scanner_network.py:130` — `findings` | Liste de dicts, un par port ouvert détecté |
| `config.py:15` — `ALLOWED_TARGETS` | `["localhost", "127.0.0.1"]` |
| `config.py:27` — `ALLOWED_PORTS` | `[22, 80, 443, 3306, 5432, 6379, 27017]` |
| `scanner_network.py:53` — `valid_ports` | Liste filtrée par compréhension de liste |

---

## Classes et objets

| Classe | Fichier | Rôle |
|--------|---------|------|
| `NetworkScanner` | `scanner_network.py` | Scan des ports TCP et récupération des bannières |
| `RiskScorer` | `risk_scorer.py` | Calcul du score de risque 0-100 |
| `ReportManager` | `report_manager.py` | Sauvegarde JSON + insertion MongoDB |
| `HtmlReporter` | `html_reporter.py` | Génération du rapport HTML |
| `SecurityAudit` | `main.py` | Orchestration de tout l'audit |

---

## Modules utilisés

| Module | Type | Rôle |
|--------|------|------|
| `socket` | natif Python | Connexions réseau TCP (scan des ports) |
| `os` | natif Python | Gestion des chemins de fichiers |
| `json` | natif Python | Sérialisation des rapports |
| `logging` | natif Python | Logs structurés avec niveaux (INFO, WARNING...) |
| `re` | natif Python | Expressions régulières (validation, sanitisation) |
| `datetime` | natif Python | Horodatage des rapports |
| `pymongo` | externe | Connexion et requêtes MongoDB |
| `flask` | externe | Serveur API REST |
| `flask_cors` | externe | Autorisation des requêtes cross-origin (dashboard) |

---

## Infrastructure Docker

| Conteneur | Port | Rôle |
|-----------|------|------|
| `guardianpy_mongo` | `27018` | Base de données MongoDB |
| `guardianpy_api` | `5000` | API Flask (`/api/audits`, `/api/stats`) |
| `guardianpy_dashboard` | `3000` | Dashboard Next.js |

---

## Commandes utiles

### Lancer les conteneurs
```bash
docker compose up -d
```

### Lancer un scan
```powershell
$env:MONGO_URI = "mongodb://localhost:27018"
$env:MONGO_DB  = "guardianpy"
py src/main.py
```

### Accéder au dashboard
```
http://localhost:3000
```

### Tout arrêter (fin de session)
```powershell
# Arrêter les conteneurs Docker
docker compose -f "C:\Users\alexi\OneDrive\Bureau\PSTB\guardian.py\docker-compose.yml" down

# Arrêter le MongoDB Windows natif
net stop MongoDB

# Vérifier que tout est fermé (doit retourner vide)
netstat -ano | findstr :27017
netstat -ano | findstr :5000
netstat -ano | findstr :3000
```
