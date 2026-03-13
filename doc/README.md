# GuardianPy — Documentation

## Présentation

GuardianPy est un Audit-Bot DevSecOps en Python.
Il scanne les ports réseau d'une machine, détecte les services exposés,
calcule un score de risque et génère des rapports (JSON, HTML, MongoDB).

---

## Architecture du projet

```
guardian.py/
├── src/
│   ├── config.py            # Constantes et variables d'environnement
│   ├── scanner_network.py   # Scan des ports + récupération des bannières
│   ├── report_manager.py    # Sauvegarde JSON + MongoDB
│   ├── risk_scorer.py       # Calcul du score de risque 0-100
│   ├── html_reporter.py     # Génération du rapport HTML
│   ├── main.py              # Point d'entrée principal
│   └── api.py               # API Flask pour le dashboard
├── dashboard/               # Dashboard Next.js (temps réel)
├── reports/                 # Rapports générés (ignoré par git)
├── doc/                     # Documentation
├── .env.example             # Template de configuration
├── .gitignore
└── requirements.txt
```

---

## Lancer le projet

### Audit réseau
```bash
py src/main.py
```

### Audit en mode simulation (sans connexion réelle)
```bash
$env:DRY_RUN = "true"
py src/main.py
```

### API Flask (pour le dashboard)
```bash
py src/api.py
```

### Dashboard Next.js
```bash
cd dashboard
npm run dev
# Ouvrir http://localhost:3000
```

### Outils de sécurité
```bash
py -m bandit -r src/      # Analyse statique du code
py -m pip_audit            # CVE dans les dépendances
```

---

## Fichiers de documentation détaillée

| Fichier | Contenu |
|---------|---------|
| [architecture.md](architecture.md) | Schéma de flux et interactions entre modules |
| [modules.md](modules.md) | Description détaillée de chaque classe et méthode |
| [securite.md](securite.md) | Règles de sécurité appliquées |
| [api.md](api.md) | Documentation des routes de l'API Flask |
