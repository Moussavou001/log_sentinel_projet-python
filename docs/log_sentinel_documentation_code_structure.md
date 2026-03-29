# Log Sentinel — Documentation Technique du Code

---

**Titre :** Documentation technique — Structure du code et architecture modulaire
**Projet :** Log Sentinel — Analyseur de logs Blue Team
**Auteur :** NAOMIE NGWIDJOMBY MOUSSAVOU
**Parcours :** Master 1 Cybersécurité
**Module :** Python
**Date :** Mars 2026
**Version :** 1.0.0

---

## Table des matières

1. [Architecture du projet](#1-architecture-du-projet)
2. [Flux de données — Pipeline complet](#2-flux-de-données--pipeline-complet)
3. [Description détaillée des modules](#3-description-détaillée-des-modules)
   - 3.1 [main.py — Point d'entrée CLI](#31-mainpy--point-dentrée-cli)
   - 3.2 [app.py — Interface web Streamlit](#32-apppy--interface-web-streamlit)
   - 3.3 [src/\_\_init\_\_.py — Métadonnées du paquet](#33-src__init__py--métadonnées-du-paquet)
   - 3.4 [src/loader.py — Chargement et détection de format](#34-srcloaderpy--chargement-et-détection-de-format)
   - 3.5 [src/parser.py — Parsing des lignes de log](#35-srcparserpy--parsing-des-lignes-de-log)
   - 3.6 [src/detector.py — Détection d'attaques](#36-srcdetectorpy--détection-dattaques)
   - 3.7 [src/statistics.py — Calcul de statistiques](#37-srcstatisticspy--calcul-de-statistiques)
   - 3.8 [src/osint.py — Enrichissement OSINT des IPs](#38-srcosintpy--enrichissement-osint-des-ips)
   - 3.9 [src/reporter.py — Génération du rapport HTML](#39-srcreporterpy--génération-du-rapport-html)
4. [Structures de données](#4-structures-de-données)
5. [Configuration et dépendances](#5-configuration-et-dépendances)
6. [Tests unitaires](#6-tests-unitaires)

---

## 1. Architecture du projet

### 1.1 Arborescence des fichiers

```
log_sentinel/
├── main.py                  ← Point d'entrée CLI (argparse + Rich)
├── app.py                   ← Interface web interactive (Streamlit)
├── requirements.txt         ← Dépendances Python du projet
├── README.md                ← Guide de démarrage rapide
├── samples/
│   └── sample_access.log    ← Fichier de log d'exemple pour les tests manuels
├── src/
│   ├── __init__.py          ← Métadonnées du paquet, export de LogLoader
│   ├── loader.py            ← Chargement fichier + détection de format
│   ├── parser.py            ← Parsing de lignes brutes → dataclass LogEntry
│   ├── detector.py          ← Détection d'attaques → dataclass Alert
│   ├── statistics.py        ← Calcul de statistiques agrégées → dict
│   ├── osint.py             ← Enrichissement IP via ip-api.com
│   └── reporter.py          ← Génération du rapport HTML auto-contenu
└── tests/
    ├── __init__.py
    ├── test_detector.py     ← 13 tests (AttackDetector + LogParser)
    └── test_statistics.py   ← 12 tests (LogStatistics + LogLoader)
```

---

📸 **CAPTURE D'ÉCRAN** — *Arborescence du projet telle qu'elle apparaît dans l'explorateur de VS Code ou dans un terminal (`tree /F` sous Windows ou `tree` sous Linux), montrant la structure `src/`, `tests/`, `samples/` et les fichiers racines.*
> *(Insérer ici la capture)*

---

### 1.2 Description de chaque fichier

| Fichier | Rôle |
|---|---|
| `main.py` | Orchestre l'ensemble du pipeline depuis la ligne de commande. Prend un fichier de log en argument, appelle successivement tous les modules `src/`, affiche les résultats avec Rich et génère un rapport HTML. |
| `app.py` | Interface web Streamlit permettant de piloter la même analyse depuis un navigateur, avec dépôt de fichier par glisser-déposer, affichage de tableaux interactifs et visualisations. |
| `src/__init__.py` | Déclare les métadonnées du paquet (`__version__`, `__author__`, `__module__`, `__license__`) et exporte `LogLoader` comme symbole public. |
| `src/loader.py` | Lit un fichier de log depuis le disque avec repli d'encodage UTF-8 → Latin-1, et détecte automatiquement son format (Apache, Nginx, Syslog). |
| `src/parser.py` | Convertit chaque ligne brute en objet structuré `LogEntry` (dataclass) selon le format détecté. Les lignes non parsables sont silencieusement ignorées. |
| `src/detector.py` | Analyse les entrées parsées pour détecter des attaques : injections SQL/XSS/commandes, traversée de répertoire, fichiers sensibles, agents malveillants, force brute et scans d'énumération. |
| `src/statistics.py` | Calcule des métriques agrégées (total requêtes, IPs uniques, distribution des codes HTTP, top URIs, taux d'erreur...) sous forme de dictionnaire Python. |
| `src/osint.py` | Interroge l'API publique `ip-api.com` pour enrichir les IPs suspectes avec des données de géolocalisation (pays, ville, FAI, statut proxy). |
| `src/reporter.py` | Génère un rapport HTML auto-contenu (CSS intégré, aucune dépendance externe) résumant score de risque, alertes, statistiques et données OSINT. |
| `samples/sample_access.log` | Fichier de log Apache fourni avec le projet pour valider rapidement le bon fonctionnement de l'outil. |
| `tests/test_detector.py` | 13 tests unitaires couvrant `AttackDetector` (6 types de signatures, force brute, scan) et `LogParser` (parsing valide, ligne invalide, filtrage). |
| `tests/test_statistics.py` | 12 tests unitaires couvrant `LogStatistics` (calculs agrégés) et `LogLoader` (chargement, encodage, détection de format). |

---

## 2. Flux de données — Pipeline complet

Le pipeline de Log Sentinel est linéaire et entièrement basé sur le passage de structures Python d'un module à l'autre. Les deux points d'entrée (`main.py` et `app.py`) partagent exactement les mêmes modules `src/` ; seule la couche de présentation diffère.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ENTRÉE UTILISATEUR                          │
│          -f fichier.log  /  upload via Streamlit                    │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LogLoader.load(filepath)                                           │
│  → list[str]   (lignes brutes, encodage résolu automatiquement)     │
│                                                                     │
│  LogLoader.detect_format(lines)                                     │
│  → "apache" | "nginx" | "syslog" | "unknown"                        │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LogParser.parse_all(lines, fmt)                                    │
│  → list[LogEntry]   (dataclass : ip, timestamp, method, uri,        │
│                      status_code, size, user_agent)                 │
│                                                                     │
│  ↓ conversion explicite en list[dict] dans main.py / app.py         │
│    (clé "status" au lieu de "status_code" pour le détecteur)        │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  AttackDetector.analyze(entries)        [ou appels individuels CLI] │
│    ├── detect_signature(entry)  x N      → list[Alert]              │
│    ├── detect_brute_force(entries)      → list[Alert]               │
│    └── detect_scan(entries)            → list[Alert]                │
│  → list[Alert]   (dataclass : attack_type, ip, uri,                 │
│                   user_agent, details)                              │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LogStatistics.compute(entries)                                     │
│  → dict  {total_requests, unique_ips, top_ips, status_codes,        │
│            top_uris, top_user_agents, methods, error_rate}          │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
              ┌─────────────┴──────────────┐
              │                            │
              ▼                            ▼
┌─────────────────────────┐  ┌─────────────────────────────────────────┐
│  OSINTChecker.check_ips │  │  HTMLReporter.generate(                 │
│  (top 5 IPs suspectes)  │  │    alerts, stats, osint_data,           │
│  → dict {ip: {country,  │  │    output_path)                         │
│    city, isp, is_proxy}}│  │  → reports/report.html  (auto-contenu)  │
└─────────────────────────┘  └─────────────────────────────────────────┘
              │                            │
              └──────────────┬─────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     AFFICHAGE / SORTIE                              │
│  CLI  : Rich Tables + Panel de résumé avec score de risque          │
│  Web  : Streamlit dashboard (métriques, tableaux, graphiques)       │
│  HTML : rapport statique auto-contenu dans reports/report.html      │
└─────────────────────────────────────────────────────────────────────┘
```

### Remarque sur la conversion LogEntry vers dict

Après le parsing, `main.py` et `app.py` convertissent explicitement les objets `LogEntry` en dictionnaires Python avant de les passer à `AttackDetector` et `LogStatistics`. Lors de cette conversion, le champ `status_code` de `LogEntry` est renommé en `status` pour s'aligner avec la convention attendue par `AttackDetector`. `LogStatistics.compute()` gère les deux noms de clé grâce à son helper interne `_get()`.

### Score de risque final

Le score de risque (0 à 100) est calculé de manière identique dans `main.py` et `app.py` selon la formule suivante :

```
score = min(50, nb_alertes × 2)
      + min(30, taux_erreur × 0.6)
      + (20 si présence d'alertes de type brute_force, scan,
              sql_injection ou command_injection, sinon 0)

score_final = min(100, score)
```

| Plage | Niveau de risque |
|---|---|
| 0 – 19 | FAIBLE |
| 20 – 49 | MODÉRÉ |
| 50 – 74 | ÉLEVÉ |
| 75 – 100 | CRITIQUE |

---

## 3. Description détaillée des modules

### 3.1 `main.py` — Point d'entrée CLI

**Rôle :** Orchestrer l'intégralité du pipeline depuis la ligne de commande. Ce fichier ne contient aucune logique métier propre ; il assure uniquement le câblage des modules `src/`, la gestion des arguments CLI, et la présentation des résultats via la bibliothèque **Rich**.

**Fonctions clés :**

| Fonction | Description |
|---|---|
| `build_parser()` | Construit et retourne le parseur `argparse`. Déclare tous les arguments CLI (`-f`, `--bf-threshold`, `--scan-threshold`, `--report`, `--check-ip`, `--output-dir`). |
| `print_banner(console)` | Affiche la bannière ASCII de Log Sentinel dans un `Rich Panel` avec bordure rouge. |
| `print_alerts(console, alerts)` | Affiche les alertes détectées dans un `Rich Table` coloré (couleur par type d'attaque). |
| `print_stats(console, stats)` | Affiche les statistiques globales sous forme de plusieurs `Rich Table` (résumé, top IPs, codes HTTP, top URIs, méthodes HTTP). |
| `main()` | Fonction principale : enchaîne chargement, détection de format, parsing, détection, statistiques, OSINT optionnel, génération du rapport HTML, et affiche le résumé final avec score de risque. |

**Arguments CLI disponibles :**

| Argument | Type | Défaut | Description |
|---|---|---|---|
| `-f`, `--file` | `str` | obligatoire | Chemin vers le fichier de log à analyser |
| `--bf-threshold` | `int` | `5` | Seuil de déclenchement alerte brute-force (nb d'erreurs 401/403 par IP) |
| `--scan-threshold` | `int` | `10` | Seuil de déclenchement alerte scan (nb d'URIs distinctes par IP) |
| `--report` / `--no-report` | `bool` | `True` | Active ou désactive la génération du rapport HTML |
| `--check-ip` | `flag` | `False` | Active la vérification OSINT des IPs suspectes |
| `--output-dir` | `str` | `"reports"` | Répertoire de destination du rapport HTML |

**Particularité de la barre de progression :** Dans `main()`, la détection par signature est découpée en chunks (1/20e du total d'entrées) pour animer la barre de progression Rich de façon fluide, tandis que les détections brute-force et scan (opérations globales rapides) sont exécutées après.

---

### 3.2 `app.py` — Interface web Streamlit

**Rôle :** Fournir une interface graphique accessible depuis un navigateur web. L'utilisateur dépose un fichier de log, configure les seuils de détection dans la barre latérale, puis consulte les résultats organisés en onglets : alertes de sécurité, statistiques, données OSINT, et rapport HTML téléchargeable.

**Comportement clé :**
- Utilise `st.session_state` pour mettre en cache les résultats d'analyse et éviter de rejouer le pipeline à chaque interaction Streamlit (rerenders).
- Appelle `detector.analyze()` (point d'entrée unique du détecteur) contrairement à `main.py` qui appelle les trois méthodes de détection individuellement pour piloter la barre de progression.
- Partage exactement les mêmes modules `src/` que le CLI : la logique métier est identique, seule la couche de présentation diffère.
- Applique un thème CSS sombre personnalisé cohérent avec le rapport HTML généré.

---

📸 **CAPTURE D'ÉCRAN** — *Interface Streamlit (app.py) ouverte dans un navigateur : barre latérale avec les options, zone de dépôt du fichier de log, et aperçu du tableau de bord avec les métriques clés.*
> *(Insérer ici la capture)*

---

### 3.3 `src/__init__.py` — Métadonnées du paquet

**Rôle :** Déclarer les métadonnées du paquet Python et définir l'interface publique exportée.

**Contenu :**

```python
__version__ = "1.0.0"
__author__  = "NAOMIE NGWIDJOMBY MOUSSAVOU"
__module__  = "Python / Master 1 Cybersécurité"
__license__ = "MIT"

from .loader import LogLoader
__all__ = ["LogLoader"]
```

`LogLoader` est la seule classe exportée dans `__all__`. Les autres classes (`LogParser`, `AttackDetector`, etc.) sont importées directement par chemin complet (`from src.detector import AttackDetector`) dans `main.py` et `app.py`.

---

### 3.4 `src/loader.py` — Chargement et détection de format

**Rôle :** Lire un fichier de log depuis le disque et identifier automatiquement son format.

#### Classe `LogLoader`

**Constantes de classe :**

| Constante | Valeur | Description |
|---|---|---|
| `_SAMPLE_SIZE` | `10` | Nombre de lignes échantillonnées en début de fichier pour la détection de format |
| `_ENCODINGS` | `["utf-8", "latin-1"]` | Séquence d'encodages essayés dans l'ordre lors de la lecture |

**Expressions régulières de détection (module-level, pré-compilées) :**

| Variable | Format cible | Motif détecté |
|---|---|---|
| `_APACHE_PATTERN` | Apache Combined/Common Log | `IP - user [DD/Mon/YYYY:HH:MM:SS ±HHMM] "METHOD URI HTTP/x.x" CODE` |
| `_NGINX_PATTERN` | Nginx access log | Identique à Apache mais requiert également les champs referer et user-agent entre guillemets |
| `_SYSLOG_PATTERN` | Syslog RFC 3164 | `Mon DD HH:MM:SS hostname process[pid]:` |

**Méthodes publiques :**

**`load(filepath: str) → list[str]`**

Lit le fichier désigné par `filepath` et retourne la liste de ses lignes non vides, avec espaces en fin de ligne supprimés. La lecture est tentée successivement avec les encodages de `_ENCODINGS` (UTF-8 d'abord, puis Latin-1). En cas d'échec des deux encodages, `UnicodeDecodeError` est relevée avec un message contextuel.

Exceptions levées :
- `FileNotFoundError` : si le fichier n'existe pas ou si le chemin pointe vers un répertoire.
- `UnicodeDecodeError` : si aucun encodage n'a permis de lire le fichier.
- `OSError` : si une erreur système survient lors de l'ouverture.

**`detect_format(lines: list[str]) → str`**

Détermine le format du log par un algorithme de vote par score : pour chacune des `_SAMPLE_SIZE` premières lignes, le pattern correspondant à chaque format candidat est testé et son score incrémenté en cas de correspondance. Le format ayant obtenu le score maximal est retourné. Si aucun format n'obtient de correspondance, `"unknown"` est retourné.

```
Algorithme de vote :
  scores = {"nginx": 0, "apache": 0, "syslog": 0}
  Pour chaque ligne de l'échantillon :
      Si _NGINX_PATTERN correspond  → scores["nginx"]  += 1
      Sinon si _APACHE_PATTERN      → scores["apache"] += 1
      Sinon si _SYSLOG_PATTERN      → scores["syslog"] += 1
  Retourner argmax(scores) si max > 0, sinon "unknown"
```

**Remarque sur la priorité Nginx/Apache :** Le pattern Nginx est testé en premier car il est plus spécifique (il impose la présence de referer et user-agent entre guillemets). Le pattern Apache, plus permissif, est testé en fallback pour ne pas absorber les lignes Nginx.

---

### 3.5 `src/parser.py` — Parsing des lignes de log

**Rôle :** Convertir chaque ligne brute de log en un objet structuré `LogEntry` (dataclass) exploitable par les modules aval.

#### Dataclass `LogEntry`

Voir section [4. Structures de données](#4-structures-de-données).

#### Classe `LogParser`

**Expressions régulières (module-level, pré-compilées) :**

| Variable | Format | Groupes capturés |
|---|---|---|
| `_APACHE_PATTERN` | Apache Combined Log | `ip, timestamp, method, uri, status_code, size, referer, user_agent` |
| `_NGINX_PATTERN` | Nginx access log | Identique à `_APACHE_PATTERN` (même regex Combined Log Format) |
| `_SYSLOG_PATTERN` | Syslog RFC 3164 | `timestamp, host, process, message` |

**Méthodes privées :**

| Méthode | Description |
|---|---|
| `_parse_apache(line)` | Applique `_APACHE_PATTERN` sur la ligne. Retourne `LogEntry` ou `None`. La valeur `"-"` dans le champ `size` est normalisée en chaîne vide. |
| `_parse_nginx(line)` | Identique à `_parse_apache` (même format Combined Log). |
| `_parse_syslog(line)` | Applique `_SYSLOG_PATTERN`. Mappe `host` → `ip`, `process` → `method`, `message` → `uri`. Les champs `status_code`, `size` et `user_agent` sont laissés vides. |

**Méthodes publiques :**

**`parse_line(line: str, fmt: str) → LogEntry | None`**

Parse une seule ligne selon le format spécifié. Si `fmt` vaut `"unknown"`, les trois parseurs sont essayés dans l'ordre (Apache, Nginx, Syslog) et le premier résultat valide est retourné. Retourne `None` si aucun parseur ne reconnaît la ligne.

**`parse_all(lines: list[str], fmt: str) → list[LogEntry]`**

Itère sur toutes les lignes, appelle `parse_line` pour chacune, et accumule uniquement les `LogEntry` non nulles. Les lignes non parsables sont silencieusement ignorées (aucune exception, aucun log d'erreur).

---

### 3.6 `src/detector.py` — Détection d'attaques

**Rôle :** Analyser les entrées de log (sous forme de dictionnaires) pour détecter des comportements malveillants et produire des objets `Alert`.

#### Dictionnaire `ATTACK_PATTERNS`

Six expressions régulières pré-compilées au chargement du module, regroupées dans un dictionnaire `dict[str, re.Pattern]` :

| Clé | Cible | Exemples de motifs détectés |
|---|---|---|
| `sql_injection` | URI | `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `INSERT INTO`, `' OR '`, `--` |
| `xss` | URI | `<script`, `javascript:`, `onerror=`, `onload=`, `alert(` |
| `path_traversal` | URI | `../`, `..\`, `/etc/passwd`, `/etc/shadow`, `C:\Windows` |
| `command_injection` | URI | `;ls`, `|cat`, `$(`, `&&rm`, `` `whoami` `` |
| `sensitive_files` | URI | `.env`, `.git`, `.htaccess`, `wp-config.php`, `/etc/passwd`, `id_rsa` |
| `malicious_ua` | User-Agent | `sqlmap`, `nikto`, `nmap`, `burp`, `wpscan`, `masscan`, `metasploit`, `hydra`, `dirbuster` |

Tous les patterns sont compilés avec le flag `re.IGNORECASE`.

#### Dataclass `Alert`

Voir section [4. Structures de données](#4-structures-de-données).

#### Classe `AttackDetector`

**Configuration :**

```python
CONFIG: dict[str, int] = {
    "BRUTE_FORCE_THRESHOLD": 5,   # modifiable par l'argument --bf-threshold
    "SCAN_THRESHOLD": 10,         # modifiable par l'argument --scan-threshold
}
```

Ces valeurs sont directement mutables depuis `main.py` (`detector.CONFIG["BRUTE_FORCE_THRESHOLD"] = args.bf_threshold`), permettant une configuration dynamique sans sous-classement.

**Méthodes publiques :**

**`detect_signature(entry: dict) → list[Alert]`**

Analyse une seule entrée de log. Applique les cinq patterns URI sur le champ `uri` et le pattern `malicious_ua` sur le champ `user_agent`. Retourne une liste d'alertes (peut en contenir plusieurs si plusieurs patterns correspondent sur la même ligne).

**`detect_brute_force(entries: list[dict]) → list[Alert]`**

Vue globale sur toutes les entrées. Compte les réponses `401` et `403` par adresse IP avec `collections.Counter`. Génère une alerte `brute_force` pour chaque IP dont le compteur est **strictement supérieur** au seuil (`BRUTE_FORCE_THRESHOLD`, défaut : 5). L'alerte est contextée avec la dernière entrée observée pour cette IP.

**`detect_scan(entries: list[dict]) → list[Alert]`**

Vue globale. Pour chaque IP, accumule un ensemble (`set`) d'URIs distinctes, le total de requêtes et le nombre de réponses `404`. Génère une alerte `scan` si les deux critères suivants sont réunis simultanément :
- Nombre d'URIs distinctes **strictement supérieur** à `SCAN_THRESHOLD` (défaut : 10)
- Proportion de réponses 404 **strictement supérieure** à 50 %

**`analyze(entries: list[dict]) → list[Alert]`**

Point d'entrée unique du détecteur (utilisé par `app.py`). Enchaîne les trois détections et retourne la liste concaténée de toutes les alertes, dans l'ordre : signatures, puis brute-force, puis scans.

---

### 3.7 `src/statistics.py` — Calcul de statistiques

**Rôle :** Calculer un ensemble de métriques agrégées à partir des entrées de log parsées, sous la forme d'un dictionnaire Python standard.

#### Classe `LogStatistics`

**Méthode publique :**

**`compute(entries: list) → dict`**

Accepte une liste d'entrées pouvant être soit des `LogEntry` (dataclass), soit des `dict`. La compatibilité est assurée par le helper interne `_get(entry, key)` qui tente d'abord `getattr` (dataclass) puis `.get()` (dict).

Gestion duale du code HTTP : le champ de statut peut s'appeler `status_code` (convention `LogEntry`) ou `status` (convention dict du pipeline). `compute()` essaie les deux clés dans l'ordre.

**Structure du dictionnaire retourné :**

| Clé | Type | Description |
|---|---|---|
| `total_requests` | `int` | Nombre total d'entrées dans la liste |
| `unique_ips` | `int` | Nombre d'adresses IP distinctes |
| `top_ips` | `list[tuple[str, int]]` | 10 IPs les plus actives, triées par fréquence décroissante |
| `status_codes` | `dict[int, int]` | Distribution des codes HTTP `{code: occurrences}` |
| `top_uris` | `list[tuple[str, int]]` | 10 URIs les plus demandées, triées par fréquence décroissante |
| `top_user_agents` | `list[tuple[str, int]]` | 5 User-Agents les plus fréquents |
| `methods` | `dict[str, int]` | Distribution des méthodes HTTP `{METHOD: occurrences}` |
| `error_rate` | `float` | Pourcentage de requêtes 4xx/5xx arrondi à 2 décimales |

En cas de liste vide en entrée, toutes les clés sont retournées avec leurs valeurs zéro/vides (pas d'exception).

**Implémentation :** Utilise `collections.Counter` pour les comptages fréquentiels et `defaultdict` pour les agrégations par IP. Les méthodes HTTP sont normalisées en majuscules (`str.upper()`).

---

### 3.8 `src/osint.py` — Enrichissement OSINT des IPs

**Rôle :** Interroger l'API publique `ip-api.com` pour enrichir les adresses IP suspectes avec des métadonnées de géolocalisation et de réputation réseau.

**Constantes de module :**

```python
_IP_API_BASE_URL = "http://ip-api.com/json/{ip}"
_REQUEST_TIMEOUT = 3  # secondes
```

#### Classe `OSINTChecker`

**`check_ip(ip: str) → dict`**

Effectue un appel HTTP GET sur `http://ip-api.com/json/{ip}` avec un timeout de 3 secondes. En cas de succès (`status == "success"` dans la réponse JSON), retourne un dictionnaire avec les champs suivants :

| Clé | Type | Description |
|---|---|---|
| `country` | `str` | Pays de l'adresse IP |
| `city` | `str` | Ville associée |
| `isp` | `str` | Fournisseur d'accès Internet |
| `is_proxy` | `bool` | `True` si l'IP est identifiée comme proxy, VPN ou nœud Tor |

En cas d'erreur (timeout, erreur réseau, réponse non-JSON, statut API non `"success"`), retourne un dictionnaire vide `{}` sans lever d'exception. Ce comportement défensif garantit que l'absence de connectivité réseau ne bloque pas le reste du pipeline.

**`check_ips(ips: list[str], max_ips: int = 5) → dict[str, dict]`**

Vérifie les `max_ips` premières adresses de la liste fournie en appelant `check_ip()` successivement. Retourne un dictionnaire `{ip: résultat}`.

**Limitation :** L'API `ip-api.com` en version gratuite impose une limite de fréquence (environ 45 requêtes par minute). La limite de 5 IPs par analyse garantit que le projet reste dans les quotas sans clé API.

---

### 3.9 `src/reporter.py` — Génération du rapport HTML

**Rôle :** Produire un rapport HTML auto-contenu (toute la feuille de style est intégrée dans le fichier, sans dépendance CDN ni fichier externe) résumant l'analyse de sécurité dans un format professionnel de style « terminal Blue Team ».

#### Dictionnaire `ATTACK_SCORES`

Pondération par type d'attaque pour le calcul du score de risque dans le rapport HTML :

| Type d'attaque | Score |
|---|---|
| `brute_force` | 25 |
| `sql_injection` | 20 |
| `command_injection` | 20 |
| `xss` | 15 |
| `path_traversal` | 15 |
| `scan` | 10 |
| `sensitive_files` | 10 |
| `malicious_ua` | 5 |

Le score HTML est calculé par sommation des scores individuels, plafonné à 100 via `min(score, 100)`. Ce calcul est distinct du score de risque de `main.py`/`app.py` (qui utilise une formule différente).

#### Fonctions privées de rendu HTML

Le rapport est construit par assemblage de sections HTML générées par des fonctions dédiées :

| Fonction | Section générée |
|---|---|
| `_render_header(generated_at)` | En-tête avec titre, date et badge « BLUE TEAM » |
| `_render_risk(alerts)` | Score de risque global avec barre de progression colorée et décompte par type |
| `_render_stats(stats)` | 4 cartes de statistiques (requêtes totales, IPs uniques, taux d'erreur, alertes) |
| `_render_alerts(alerts)` | Tableau des alertes avec badges colorés par type d'attaque |
| `_render_top_ips(stats)` | Tableau Top 10 IPs |
| `_render_top_uris(stats)` | Tableau Top 10 URIs |
| `_render_http_codes(stats)` | Distribution des codes HTTP avec code couleur (2xx vert, 3xx bleu, 4xx orange, 5xx rouge) |
| `_render_osint(osint_data)` | Grille de cartes OSINT par IP |
| `_render_footer(generated_at)` | Pied de page avec date et mention d'usage |

**Helpers :**
- `_h(value)` : échappe toute valeur pour insertion HTML sécurisée (`html.escape`).
- `_compute_risk_score(alerts)` : calcule le score en sommant les pondérations `ATTACK_SCORES`.
- `_risk_class(score)`, `_risk_label(score)`, `_bar_color(score)` : déterminent le style CSS conditionnel selon le niveau de risque.

#### Classe `HTMLReporter`

**`generate(alerts, stats, osint_data, output_path) → str`**

Assemble toutes les sections HTML, entoure le corps avec un document HTML5 complet incluant le bloc `<style>` contenant la constante `CSS`, écrit le fichier à `output_path` (les répertoires parents sont créés automatiquement si nécessaire), et retourne le chemin absolu du fichier généré.

---

📸 **CAPTURE D'ÉCRAN** — *Rapport HTML généré (`reports/report.html`) ouvert dans un navigateur : en-tête avec score de risque, cartes de statistiques, tableau des alertes avec badges colorés, et section OSINT.*
> *(Insérer ici la capture)*

---

## 4. Structures de données

### 4.1 Dataclass `LogEntry` — `src/parser.py`

Représente une entrée de log unique après parsing. Tous les champs sont de type `str` avec une valeur par défaut de chaîne vide.

| Champ | Type | Description | Exemple |
|---|---|---|---|
| `ip` | `str` | Adresse IP source de la requête | `"192.168.1.1"` |
| `timestamp` | `str` | Horodatage brut tel qu'extrait du log | `"28/Mar/2026:10:00:00 +0000"` |
| `method` | `str` | Méthode HTTP (Apache/Nginx) ou processus (Syslog) | `"GET"`, `"POST"` |
| `uri` | `str` | URI de la ressource demandée (Apache/Nginx) ou message (Syslog) | `"/index.html"` |
| `status_code` | `str` | Code de réponse HTTP | `"200"`, `"404"`, `"403"` |
| `size` | `str` | Taille de la réponse en octets (chaîne vide si absent ou `-`) | `"1234"` |
| `user_agent` | `str` | Chaîne User-Agent du client | `"Mozilla/5.0"` |

**Remarques :**
- Pour le format Syslog, les champs `status_code`, `size` et `user_agent` sont laissés vides car le format ne les contient pas.
- Tous les champs sont des chaînes (`str`), y compris `status_code` — la conversion en `int` est effectuée à la demande par les modules consommateurs.
- Lors du passage au détecteur et aux statistiques, les objets `LogEntry` sont convertis en `dict` avec le champ `status_code` renommé en `status`.

### 4.2 Dataclass `Alert` — `src/detector.py`

Représente une alerte de sécurité générée par l'un des trois détecteurs. Tous les champs sont obligatoires (pas de valeur par défaut).

| Champ | Type | Description | Exemple |
|---|---|---|---|
| `attack_type` | `str` | Catégorie de l'attaque détectée | `"sql_injection"`, `"brute_force"`, `"scan"` |
| `ip` | `str` | Adresse IP de l'attaquant présumé | `"10.0.0.1"` |
| `uri` | `str` | URI impliquée dans l'attaque (ou `"(multiple)"` pour les scans) | `"/search?q=UNION SELECT"` |
| `user_agent` | `str` | User-Agent observé lors de l'événement | `"sqlmap/1.7.2"` |
| `details` | `str` | Description textuelle de l'alerte, incluant le motif correspondant ou le comptage | `"Pattern matched in URI: 'UNION SELECT'"` |

**Valeurs possibles de `attack_type` :**

| Valeur | Source |
|---|---|
| `"sql_injection"` | `detect_signature()` |
| `"xss"` | `detect_signature()` |
| `"path_traversal"` | `detect_signature()` |
| `"command_injection"` | `detect_signature()` |
| `"sensitive_files"` | `detect_signature()` |
| `"malicious_ua"` | `detect_signature()` |
| `"brute_force"` | `detect_brute_force()` |
| `"scan"` | `detect_scan()` |

---

## 5. Configuration et dépendances

### 5.1 Dépendances Python (`requirements.txt`)

```
requests>=2.31.0
rich>=13.7.0
streamlit>=1.32.0
pandas>=2.0.0
```

| Bibliothèque | Version minimale | Utilisation dans le projet |
|---|---|---|
| `requests` | 2.31.0 | Appels HTTP vers l'API ip-api.com dans `osint.py` |
| `rich` | 13.7.0 | Affichage en console dans `main.py` : tables colorées, panneaux, barre de progression |
| `streamlit` | 1.32.0 | Interface web interactive dans `app.py` |
| `pandas` | 2.0.0 | Manipulation et affichage de tableaux de données dans `app.py` |

**Bibliothèques de la stdlib utilisées** (aucune installation requise) : `re`, `os`, `sys`, `pathlib`, `argparse`, `collections`, `dataclasses`, `html`, `datetime`, `typing`, `unittest`, `tempfile`.

### 5.2 Commandes d'utilisation

```bash
# Activer l'environnement virtuel (Windows)
D:\Python\env\Scripts\activate

# Interface CLI — analyse simple
python main.py -f samples/sample_access.log

# Interface CLI — avec vérification OSINT et seuils personnalisés
python main.py -f samples/sample_access.log --check-ip --bf-threshold 3 --scan-threshold 5

# Interface CLI — sans génération de rapport HTML
python main.py -f samples/sample_access.log --no-report

# Interface CLI — rapport dans un répertoire personnalisé
python main.py -f samples/sample_access.log --output-dir ./output

# Interface web Streamlit
streamlit run app.py
```

---

📸 **CAPTURE D'ÉCRAN** — *Terminal montrant l'exécution de `python main.py -f samples/sample_access.log` : bannière ASCII Log Sentinel, barre de progression Rich, tableau des alertes coloré, statistiques, et panneau de résumé final avec score de risque.*
> *(Insérer ici la capture)*

---

## 6. Tests unitaires

### 6.1 Organisation

Les tests sont regroupés dans le répertoire `tests/` selon une séparation thématique :

| Fichier | Classe(s) testée(s) | Nombre de tests |
|---|---|---|
| `tests/test_detector.py` | `AttackDetector`, `LogParser` | 13 |
| `tests/test_statistics.py` | `LogStatistics`, `LogLoader` | 12 |
| **Total** | | **25** |

### 6.2 Détail des cas de test

#### `test_detector.py` — 13 tests

**Classe `TestAttackDetector` (10 tests) :**

| Test | Description | Ce qui est vérifié |
|---|---|---|
| `test_sql_injection_detected` | URI contenant `UNION SELECT * FROM users` | Alerte `sql_injection` présente |
| `test_xss_detected` | URI contenant `<script>alert(1)</script>` | Alerte `xss` présente |
| `test_path_traversal_detected` | URI `/../../../etc/passwd` | Alerte `path_traversal` présente |
| `test_sensitive_file_detected` | URI `/.env` | Alerte `sensitive_files` présente |
| `test_malicious_ua_detected` | User-Agent `sqlmap/1.7.2` | Alerte `malicious_ua` présente |
| `test_command_injection_detected` | URI `/cmd?exec=;ls -la` | Alerte `command_injection` présente |
| `test_clean_request_no_alert` | URI `/index.html`, UA `Mozilla/5.0` | Liste d'alertes vide |
| `test_brute_force_detected` | 6 réponses `401` depuis la même IP | Alerte `brute_force` présente (seuil > 5) |
| `test_brute_force_below_threshold` | 3 réponses `401` depuis la même IP | Pas d'alerte `brute_force` |
| `test_scan_detected` | 15 URIs distinctes avec réponse `404` | Alerte `scan` présente |

**Classe `TestLogParser` (3 tests) :**

| Test | Description | Ce qui est vérifié |
|---|---|---|
| `test_parse_apache_line` | Ligne Apache Combined Log valide | `ip`, `method`, `uri`, `status_code` correctement extraits |
| `test_parse_invalid_line` | Ligne texte libre non conforme | Retour `None` |
| `test_parse_all_filters_none` | 2 lignes valides + 1 invalide | `parse_all` retourne exactement 2 entrées |

#### `test_statistics.py` — 12 tests

**Classe `TestLogStatistics` (7 tests) :**

| Test | Description |
|---|---|
| `test_empty_entries` | Liste vide → `total_requests == 0`, `unique_ips == 0` |
| `test_total_requests` | 3 entrées → `total_requests == 3` |
| `test_unique_ips` | 3 entrées avec 2 IPs distinctes → `unique_ips == 2` |
| `test_top_ips` | IP la plus fréquente en première position dans `top_ips` |
| `test_error_rate` | 1 entrée 200 + 1 entrée 404 → `error_rate == 50.0` |
| `test_status_codes_counted` | Distribution correcte des codes 200, 404, 500 |
| `test_methods_counted` | Distribution correcte des méthodes GET/POST |

**Classe `TestLogLoader` (5 tests) :**

| Test | Description |
|---|---|
| `test_file_not_found` | Chemin inexistant → `FileNotFoundError` levée |
| `test_load_valid_file` | Fichier temporaire de 3 lignes → 3 lignes retournées |
| `test_empty_lines_ignored` | Fichier avec lignes vides intercalées → seules les lignes non vides retournées |
| `test_detect_apache_format` | Lignes Apache → format détecté `"apache"` |
| `test_detect_unknown_format` | Lignes texte libre → format détecté `"unknown"` |

### 6.3 Commandes d'exécution des tests

```bash
# Lancer la totalité de la suite de tests avec rapport détaillé
python -m unittest discover -s tests -v

# Lancer uniquement les tests du détecteur
python -m unittest tests.test_detector -v

# Lancer uniquement les tests des statistiques
python -m unittest tests.test_statistics -v
```

---

📸 **CAPTURE D'ÉCRAN** — *Terminal affichant le résultat de `python -m unittest discover -s tests -v` : liste des 25 tests avec leur nom, statut `ok` ou `FAIL`, et le résumé final `Ran 25 tests in X.XXXs — OK`.*
> *(Insérer ici la capture)*

---

*Document rédigé en Mars 2026 — Log Sentinel v1.0.0*
*NAOMIE NGWIDJOMBY MOUSSAVOU — Master 1 Cybersécurité — Module Python*
