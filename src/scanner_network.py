# =============================================================================
# scanner_network.py — Scan des ports réseau et récupération des bannières
# =============================================================================
# Ce fichier contient la classe NetworkScanner.
#
# Ce qu'elle fait :
#   1. Vérifie que la cible et les ports demandés sont autorisés (whitelist)
#   2. Tente une connexion TCP sur chaque port (probe)
#   3. Si le port est ouvert, essaie de lire la bannière du service
#   4. Retourne une liste de "findings" (ports ouverts trouvés)
#
# Concept Python clé : socket TCP
#   Un socket est un canal de communication réseau.
#   connect_ex() retourne 0 si la connexion réussit (port ouvert).
# =============================================================================

import socket
import logging
import re
from datetime import datetime, timezone
from config import ALLOWED_TARGETS, ALLOWED_PORTS, MAX_PORTS_PER_SCAN, SOCKET_TIMEOUT


class NetworkScanner:
    """Scanne les ports réseau d'une cible autorisée et récupère les bannières."""

    def __init__(self) -> None:
        # Le logger permet d'écrire des messages dans les logs au lieu de print()
        self.logger = logging.getLogger(__name__)

    # -------------------------------------------------------------------------
    # VALIDATION DE L'HÔTE
    # Vérifie que la cible est dans la whitelist ET qu'elle a un format valide.
    # Retourne True si OK, False sinon.
    # -------------------------------------------------------------------------
    def _validate_host(self, host: str) -> bool:
        # Étape 1 : la cible doit être dans la liste autorisée
        if host not in ALLOWED_TARGETS:
            self.logger.warning(f"Cible non autorisée : {host}")
            return False

        # Étape 2 : le format doit être une IP ou un hostname valide
        ip_pattern       = r"^(\d{1,3}\.){3}\d{1,3}$"   # ex: 192.168.1.1
        hostname_pattern = r"^[a-zA-Z0-9\-\.]{1,253}$"   # ex: localhost
        return bool(re.match(ip_pattern, host) or re.match(hostname_pattern, host))

    # -------------------------------------------------------------------------
    # VALIDATION DES PORTS
    # Filtre la liste pour ne garder que les ports autorisés et valides.
    # Retourne une liste d'entiers propre.
    # -------------------------------------------------------------------------
    def _validate_ports(self, ports: list) -> list[int]:
        valid = [
            p for p in ports
            # Le port doit être un entier, dans la whitelist, et dans la plage 1-65535
            if isinstance(p, int) and p in ALLOWED_PORTS and 1 <= p <= 65535
        ]
        # On limite au maximum autorisé pour éviter les scans massifs
        return valid[:MAX_PORTS_PER_SCAN]

    # -------------------------------------------------------------------------
    # PROBE D'UN PORT (test de connexion)
    # Tente une connexion TCP sur host:port.
    # Retourne True si le port est ouvert, False sinon.
    #
    # "with socket.socket() as s:" garantit que le socket est toujours fermé,
    # même en cas d'erreur (équivalent du try/finally).
    # -------------------------------------------------------------------------
    def _probe_port(self, host: str, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(SOCKET_TIMEOUT)          # Timeout obligatoire
                result = s.connect_ex((host, port))   # 0 = connexion réussie
                return result == 0
        except (socket.timeout, socket.error, OSError) as e:
            self.logger.debug(f"Erreur probe {host}:{port} — {type(e).__name__}")
            return False

    # -------------------------------------------------------------------------
    # RÉCUPÉRATION DE BANNIÈRE
    # Une bannière est le message qu'un service envoie quand on se connecte.
    # Ex: "HTTP/1.1 200 OK Server: Apache/2.4.51"
    # Pour les services web (ports 80, 443...) on envoie une requête HEAD.
    # -------------------------------------------------------------------------
    def _grab_banner(self, host: str, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(SOCKET_TIMEOUT)
                s.connect((host, port))

                # Les services web nécessitent une requête pour répondre
                if port in [80, 443, 8080, 8443]:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

                # On lit les 256 premiers octets de la réponse
                banner = s.recv(256).decode("utf-8", errors="ignore")
                return self._sanitize_banner(banner)
        except Exception as e:
            self.logger.debug(f"Bannière non récupérée {host}:{port} — {type(e).__name__}")
            return "inconnu"

    # -------------------------------------------------------------------------
    # SANITISATION DE LA BANNIÈRE
    # Nettoie les données reçues du réseau avant de les utiliser.
    # Supprime les caractères spéciaux qui pourraient corrompre les logs.
    # -------------------------------------------------------------------------
    def _sanitize_banner(self, data: str) -> str:
        # Remplace les sauts de ligne par des espaces
        clean = data.replace("\n", " ").replace("\r", " ")
        # Ne garde que les caractères ASCII imprimables (codes 32 à 126)
        clean = re.sub(r"[^\x20-\x7E]", "", clean)
        # Limite à 200 caractères pour éviter les bannières trop longues
        return clean[:200].strip()

    # -------------------------------------------------------------------------
    # SCAN PRINCIPAL — point d'entrée de la classe
    # Orchestre la validation, le probe et la récupération de bannière.
    # Retourne une liste de findings (un finding = un port ouvert détecté).
    # -------------------------------------------------------------------------
    def scan_ports(self, host: str, ports: list) -> list[dict]:
        # Validation de la cible
        if not self._validate_host(host):
            raise ValueError(f"Hôte non autorisé : {host}")

        # Validation des ports
        valid_ports = self._validate_ports(ports)
        if not valid_ports:
            raise ValueError("Aucun port valide dans la liste fournie.")

        findings: list[dict] = []
        finding_id = 1

        for port in valid_ports:
            is_open = self._probe_port(host, port)

            if is_open:
                banner = self._grab_banner(host, port)
                self.logger.info(f"Port ouvert : {host}:{port} — {banner}")

                # Chaque finding suit un format standardisé (défini dans CLAUDE.md)
                findings.append({
                    "id":        f"NET_{finding_id:02d}",          # ex: NET_01
                    "service":   f"port_{port}",                    # ex: port_80
                    "issue":     f"Port {port} ouvert sur {host}",
                    "severity":  self._get_severity(port),          # HIGH ou MEDIUM
                    "banner":    banner,                            # version du service
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                finding_id += 1

        return findings

    # -------------------------------------------------------------------------
    # NIVEAU DE SÉVÉRITÉ
    # Les ports donnant accès à des bases de données ou SSH sont classés HIGH
    # car leur exposition représente un risque élevé.
    # -------------------------------------------------------------------------
    def _get_severity(self, port: int) -> str:
        # Ports sensibles : accès direct aux données ou à la machine
        high_risk_ports = [22, 3306, 5432, 6379, 27017]
        if port in high_risk_ports:
            return "HIGH"
        return "MEDIUM"
