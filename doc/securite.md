# Règles de sécurité appliquées dans GuardianPy

## Règle 1 — Zéro secret dans le code

Les credentials (MongoDB URI) sont lus depuis les variables d'environnement.

```python
# Correct
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")

# Interdit
MONGO_URI = "mongodb://admin:motdepasse@localhost:27017"
```

**Où c'est appliqué :** `config.py`

---

## Règle 2 — Validation des entrées

Toute donnée externe est validée avant utilisation.

- **Host** : doit être dans la whitelist ET matcher un pattern IP/hostname
- **Ports** : doivent être des entiers dans ALLOWED_PORTS et entre 1-65535
- **Service MongoDB** : type str + longueur max 50

**Où c'est appliqué :** `scanner_network.py`, `report_manager.py`

---

## Règle 3 — Principe du moindre privilège

Le bot ne peut scanner que les cibles et ports définis dans `config.py`.
Aucun paramètre libre n'est accepté en entrée utilisateur.

**Où c'est appliqué :** `config.py`, `scanner_network.py`

---

## Règle 4 — Sécurité des sockets

Chaque socket a un timeout strict et est fermé via context manager.

```python
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.settimeout(SOCKET_TIMEOUT)  # obligatoire
    s.connect_ex((host, port))
# socket automatiquement fermé ici
```

**Où c'est appliqué :** `scanner_network.py`

---

## Règle 5 — Sécurité des logs

Les données réseau (bannières) sont sanitisées avant d'être loggées.
Cela empêche les injections de logs (fausser les fichiers de log avec des caractères spéciaux).

```python
def _sanitize_banner(self, data: str) -> str:
    clean = data.replace("\n", " ").replace("\r", " ")
    clean = re.sub(r"[^\x20-\x7E]", "", clean)
    return clean[:200].strip()
```

**Où c'est appliqué :** `scanner_network.py`

---

## Règle 6 — Anti-injection NoSQL

Avant toute requête MongoDB, on vérifie le type et la longueur.
pymongo échappe automatiquement les opérateurs si la valeur est une string.

```python
if not isinstance(service_name, str) or len(service_name) > 50:
    raise ValueError("Nom de service invalide")
```

**Où c'est appliqué :** `report_manager.py`

---

## Règle 7 — Anti-path traversal

Les noms de fichiers sont nettoyés et le chemin final est vérifié.

```python
safe_name = os.path.basename(filename)           # supprime les ../
full_path = os.path.abspath(os.path.join(REPORTS_DIR, safe_name))
if not full_path.startswith(REPORTS_DIR):        # vérification finale
    raise ValueError("Path traversal détecté")
```

**Où c'est appliqué :** `report_manager.py`, `html_reporter.py`

---

## Règle 8 — Gestion des exceptions

Les détails d'erreur restent dans les logs internes.
L'utilisateur reçoit uniquement un message générique.

```python
except Exception as e:
    self.logger.error(f"Détail : {type(e).__name__}")   # log interne
    return jsonify({"error": "Erreur serveur"}), 500    # message générique
```

**Où c'est appliqué :** `api.py`, `scanner_network.py`

---

## Règle 9 — Anti-XSS dans le HTML

Toutes les données insérées dans le HTML sont échappées.

```python
def _escape(self, text: str) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;")...
```

**Où c'est appliqué :** `html_reporter.py`

---

## Commandes d'audit du code

```bash
# Analyse statique — détecte les failles Python connues
py -m bandit -r src/

# CVE dans les dépendances pip
py -m pip_audit
```
