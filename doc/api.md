# Documentation de l'API Flask

## Démarrage

```bash
py src/api.py
# L'API écoute sur http://127.0.0.1:5000
```

---

## GET /api/audits

Retourne la liste complète de tous les audits stockés dans MongoDB.

### Exemple de réponse

```json
[
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
        "findings": [
            {
                "id": "NET_01",
                "service": "port_80",
                "issue": "Port 80 ouvert sur localhost",
                "severity": "MEDIUM",
                "banner": "HTTP/1.0 200 OK Server: SimpleHTTP",
                "timestamp": "2026-03-08T19:31:54+00:00"
            }
        ]
    }
]
```

### Erreur possible

```json
{"error": "Erreur serveur"}   → code HTTP 500
```

---

## GET /api/stats

Retourne les statistiques globales calculées sur tous les audits.

### Exemple de réponse

```json
{
    "total_audits": 5,
    "total_findings": 8,
    "avg_score": 12,
    "severity_breakdown": {
        "CRITICAL": 0,
        "HIGH": 3,
        "MEDIUM": 5,
        "LOW": 0
    }
}
```

---

## Tester l'API manuellement

```bash
# Depuis PowerShell
Invoke-RestMethod http://127.0.0.1:5000/api/stats
Invoke-RestMethod http://127.0.0.1:5000/api/audits
```

---

## Configuration CORS

L'API autorise les requêtes venant de n'importe quelle origine (`flask-cors`).
Cela est nécessaire pour que le dashboard Next.js (port 3000) puisse
appeler l'API (port 5000) sans être bloqué par le navigateur.
