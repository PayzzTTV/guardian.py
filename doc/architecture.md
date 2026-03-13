# Architecture de GuardianPy

## Schéma de flux

```
py src/main.py
      │
      ▼
SecurityAudit.run()
      │
      ├─── 1. NetworkScanner.scan_ports()
      │          │
      │          ├── _validate_host()     → vérifie la whitelist
      │          ├── _validate_ports()    → filtre les ports
      │          ├── _probe_port()        → connexion TCP (socket)
      │          └── _grab_banner()       → lit la réponse du service
      │                    │
      │                    └── retourne : list[dict] findings
      │
      ├─── 2. RiskScorer.compute()
      │          │
      │          ├── _compute_raw_score() → somme des poids
      │          ├── _normalize()         → score 0-100
      │          └── _risk_level()        → LOW/MEDIUM/HIGH/CRITICAL
      │                    │
      │                    └── retourne : dict {score, level, breakdown}
      │
      ├─── 3. ReportManager.save_report()
      │          │
      │          ├── _build_report()      → construit le dict complet
      │          ├── _save_json()         → écrit reports/audit_*.json
      │          └── _save_mongo()        → insère dans MongoDB
      │
      └─── 4. HtmlReporter.save_report()
                 │
                 ├── _build_html()        → génère la page HTML
                 └── _safe_path()         → chemin sécurisé
                           │
                           └── écrit reports/audit_*.html
```

## Schéma du dashboard

```
MongoDB (port 27017)
      │
      ▼
py src/api.py  (Flask — port 5000)
      │
      │  GET /api/audits
      │  GET /api/stats
      │
      ▼
npm run dev  (Next.js — port 3000)
      │
      ▼
Navigateur → http://localhost:3000
```

## Interactions entre modules

```
config.py ◄─────────────── importé par tous les modules
    │
    ├── scanner_network.py  ◄── utilisé par main.py
    ├── report_manager.py   ◄── utilisé par main.py et api.py
    ├── risk_scorer.py      ◄── utilisé par main.py
    ├── html_reporter.py    ◄── utilisé par main.py
    └── api.py              ◄── utilisé par le dashboard Next.js
```

## Stack technique

| Couche | Technologie |
|--------|-------------|
| Scan réseau | Python stdlib (socket, re) |
| Persistance | MongoDB + pymongo |
| API | Flask + flask-cors |
| Dashboard | Next.js + TypeScript + Tailwind CSS |
| Sécurité | bandit + pip-audit |
