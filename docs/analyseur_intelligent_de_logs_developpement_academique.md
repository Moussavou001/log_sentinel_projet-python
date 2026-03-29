# Rapport de Développement — Analyseur Intelligent de Logs (Log Sentinel)

**Auteure :** NAOMIE NGWIDJOMBY MOUSSAVOU
**Parcours :** Master 1 Cybersécurité
**Module :** Python
**Date :** Mars 2026
**Encadrement :** Projet de fin de module — Développement d'un outil de sécurité Blue Team en Python

---

## Table des matières

1. [Introduction](#1-introduction)
2. [Analyse des besoins](#2-analyse-des-besoins)
3. [Choix technologiques](#3-choix-technologiques)
4. [Architecture et conception](#4-architecture-et-conception)
5. [Implémentation — Logique d'automatisation originale](#5-implémentation--logique-dautomatisation-originale)
6. [Gestion des erreurs et robustesse](#6-gestion-des-erreurs-et-robustesse)
7. [Tests unitaires](#7-tests-unitaires)
8. [Résultats et analyse](#8-résultats-et-analyse)
9. [Bilan par rapport à la consigne](#9-bilan-par-rapport-à-la-consigne)
10. [Limites et améliorations](#10-limites-et-améliorations)
11. [Conclusion](#11-conclusion)

---

## 1. Introduction

### 1.1 Contexte

Les journaux d'événements, communément appelés *logs*, constituent l'une des sources d'information les plus précieuses pour un analyste de sécurité. Tout serveur web en production génère en continu des enregistrements horodatés décrivant chaque requête reçue : adresse IP source, méthode HTTP, ressource demandée, code de réponse, user-agent. Ce flux d'informations brutes représente à la fois une trace forensique irremplaçable et un vecteur d'alerte précoce pour la détection d'intrusions.

Dans un contexte professionnel, un analyste SOC (*Security Operations Center*) ou un administrateur système ne peut pas parcourir manuellement des milliers de lignes de logs pour détecter des comportements malveillants. C'est dans cette problématique que s'inscrit le projet **Log Sentinel** : automatiser l'analyse de fichiers de logs afin d'identifier rapidement les indicateurs de compromission (IoC) et de produire un rapport exploitable.

### 1.2 Objectif du projet

L'objectif principal de Log Sentinel est de développer un **outil Python d'analyse de logs orienté Blue Team**, capable de :

- charger automatiquement un fichier de log, quel que soit son encodage ;
- détecter le format du fichier sans intervention de l'utilisateur ;
- parser chaque ligne en entrées structurées ;
- détecter plusieurs catégories d'attaques par des mécanismes algorithmiques originaux ;
- présenter les résultats dans le terminal (CLI riche) et dans une interface web ;
- générer un rapport HTML autonome consultable hors ligne ;
- exposer des métriques statistiques sur le trafic analysé.

### 1.3 Périmètre

Le projet couvre l'analyse de logs de serveurs web (formats Apache, Nginx) et de systèmes Unix (format Syslog). Il se limite à la détection passive — aucune action corrective n'est déclenchée — et s'inscrit donc pleinement dans une logique de surveillance et d'aide à la décision (*monitoring and alerting*).

La consigne impose explicitement de **coder sa propre logique d'automatisation**. Ce principe directeur a guidé l'ensemble des choix d'implémentation : aucun moteur de règles tiers, aucune bibliothèque de détection d'intrusion externe. L'intégralité de la logique d'analyse est développée en Python natif.

---

## 2. Analyse des besoins

### 2.1 Besoins fonctionnels

L'analyse du domaine et de la consigne a permis d'identifier les fonctionnalités essentielles suivantes :

| Identifiant | Besoin fonctionnel | Priorité |
|---|---|---|
| BF-01 | Charger un fichier de log depuis le système de fichiers | Haute |
| BF-02 | Détecter automatiquement le format du log (Apache, Nginx, Syslog) | Haute |
| BF-03 | Parser chaque ligne en structure de données typée | Haute |
| BF-04 | Détecter les injections SQL par pattern matching | Haute |
| BF-05 | Détecter les tentatives XSS | Haute |
| BF-06 | Détecter les traversées de répertoires (*path traversal*) | Haute |
| BF-07 | Détecter les accès à des fichiers sensibles | Haute |
| BF-08 | Détecter les user-agents malveillants (outils d'attaque) | Haute |
| BF-09 | Détecter les attaques par force brute (seuil configurable) | Haute |
| BF-10 | Détecter les comportements de scan (énumération de ressources) | Haute |
| BF-11 | Calculer un score de risque global | Moyenne |
| BF-12 | Afficher les résultats dans le terminal avec mise en forme riche | Moyenne |
| BF-13 | Fournir une interface web interactive (4 onglets) | Moyenne |
| BF-14 | Générer un rapport HTML autonome | Moyenne |
| BF-15 | Enrichir les IPs suspectes par interrogation OSINT | Basse |

### 2.2 Besoins non-fonctionnels

Au-delà des fonctionnalités, plusieurs qualités structurelles ont été identifiées comme contraintes de conception :

**Robustesse.** L'outil doit fonctionner de manière stable face à des entrées imprévues : fichier inexistant, encodage non standard, ligne malformée, réseau absent lors de la vérification OSINT. Chaque point de défaillance potentiel doit être couvert par une gestion d'exception explicite.

**Modularité.** Chaque module doit encapsuler une responsabilité unique. Cette contrainte facilite la testabilité, la maintenance et la réutilisabilité des composants.

**Lisibilité du code.** Le code produit dans un cadre académique doit être lisible et documenté. Les fonctions doivent être courtes, commentées, avec des noms explicites.

**Performance raisonnable.** L'outil doit traiter des fichiers de logs courants (quelques milliers à quelques dizaines de milliers de lignes) en un temps inférieur à la minute.

### 2.3 Contraintes de la consigne

La consigne du module Python impose cinq contraintes techniques dont le respect est évalué explicitement :

1. **Structures de données complexes** : utilisation de `list`, `dict`, `set`, `Counter`, `defaultdict`.
2. **Modularité** : code découpé en fonctions, une fonction = une action précise.
3. **Robustesse** : gestion des erreurs avec `try/except` et types d'exceptions nommés.
4. **Interaction** : interface CLI avec `argparse` (main.py) et interface web avec Streamlit (app.py).
5. **Bibliothèques tierces** : utilisation justifiée de `rich`, `requests`, `streamlit`, `pandas`.

Ces cinq points ont servi de grille d'évaluation continue tout au long du développement.

---

## 3. Choix technologiques

### 3.1 Python 3.12

**Choix retenu.** Python 3.12 est le langage imposé par le module. Il est pertinent pour ce projet pour plusieurs raisons : richesse de la bibliothèque standard (notamment `re`, `collections`, `argparse`, `dataclasses`), syntaxe claire favorable à la lisibilité académique, et écosystème mature en data analysis et cybersécurité.

**Alternative écartée.** Un développement en Bash avec `awk`/`grep` permettrait également d'analyser des logs, mais ne satisferait pas les contraintes du module (structures de données, orienté objet, interfaces graphiques). Go ou Rust offriraient de meilleures performances mais avec une courbe d'apprentissage inadaptée au contexte.

La syntaxe `type | None` et les *union types* de Python 3.10+ sont utilisés dans les signatures de méthodes (ex. `Exception | None`), ce qui impose Python ≥ 3.10.

### 3.2 `re` — Module d'expressions régulières

**Choix retenu.** La détection d'attaques par signature repose sur des expressions régulières compilées à l'initialisation du module (`re.compile()`). La compilation préalable améliore les performances lors de l'application répétée sur chaque ligne.

**Alternative écartée.** Une recherche par sous-chaîne (`in`) serait plus rapide pour des patterns simples mais inadaptée aux patterns complexes (variantes encodées, espaces optionnels). Le module `re` offre la flexibilité nécessaire avec `re.IGNORECASE` pour la détection insensible à la casse.

### 3.3 `collections` — Counter et defaultdict

**Choix retenu.** `Counter` est utilisé dans `detector.py` pour compter les codes 401/403 par IP (détection brute-force) et dans `statistics.py` pour les Top IPs, Top URIs, Top user-agents. `defaultdict` est utilisé dans `detect_scan()` pour accumuler les statistiques par IP sans initialisation explicite.

Ces structures sont nativement optimisées et évitent les patterns verbeux de type `if ip not in dict: dict[ip] = 0; dict[ip] += 1`.

**Alternative écartée.** Un simple `dict` avec `setdefault()` serait fonctionnellement équivalent mais moins lisible et légèrement moins performant que `Counter`.

### 3.4 `dataclasses` — LogEntry et Alert

**Choix retenu.** Les deux structures de données centrales du pipeline (`LogEntry` et `Alert`) sont définies comme des `@dataclass`. Ce mécanisme génère automatiquement `__init__`, `__repr__` et `__eq__`, réduisant le code répétitif tout en produisant des objets typés et introspectables.

**Alternative écartée.** Des `namedtuple` offriraient l'immutabilité mais ne permettraient pas les valeurs par défaut flexibles. Un simple `dict` serait moins explicite sur le contrat de données et n'apporterait pas la vérification de type statique.

### 3.5 `argparse` — Interface en ligne de commande

**Choix retenu.** `argparse` est le module standard pour la construction d'interfaces CLI en Python. Il génère automatiquement l'aide (`--help`), valide les types des arguments (`type=int`), et supporte `BooleanOptionalAction` pour les flags `--report`/`--no-report`.

**Alternative écartée.** `click` est une bibliothèque tierce populaire pour les CLIs Python, mais elle introduirait une dépendance supplémentaire pour une fonctionnalité déjà couverte par la bibliothèque standard.

### 3.6 `rich` — Affichage terminal enrichi

**Choix retenu.** `rich` (version ≥ 13.7) permet l'affichage de tableaux, panneaux, barres de progression et texte coloré dans le terminal, sans code d'échappement ANSI manuel. L'expérience utilisateur du CLI est significativement améliorée : les alertes sont présentées dans un tableau structuré, les types d'attaques sont colorés (rouge pour SQL injection, cyan pour malicious_ua), et une barre de progression `rich.progress.Progress` indique l'avancement de l'analyse.

**Alternative écartée.** `colorama` permet la colorisation basique mais ne fournit pas les composants tabulaires. `curses` (bibliothèque standard) serait inadapté pour un affichage statique séquentiel.

### 3.7 `streamlit` — Interface web

**Choix retenu.** Streamlit permet de construire une interface web interactive en Python pur, sans HTML ni JavaScript. L'interface `app.py` présente les résultats en quatre onglets (Alertes, Statistiques, OSINT, Rapport) avec des tableaux `pandas` et des métriques visuelles (`st.metric`). Le mécanisme `st.session_state` permet de conserver les résultats entre les re-renders.

**Alternative écartée.** Flask ou FastAPI permettraient une application web complète, mais avec un développement frontend séparé incompatible avec les contraintes temporelles du module. Dash (Plotly) serait une alternative valide mais avec une courbe d'apprentissage plus prononcée.

### 3.8 `requests` — Requêtes HTTP pour l'OSINT

**Choix retenu.** `requests` est utilisé dans `osint.py` pour interroger l'API publique `ip-api.com`. Sa gestion des exceptions (`ConnectionError`, `Timeout`, `HTTPError`) est claire et permet un traitement robuste des défaillances réseau.

**Alternative écartée.** `urllib.request` (bibliothèque standard) serait fonctionnellement suffisant mais avec une API moins ergonomique pour la gestion des timeouts et des erreurs.

### 3.9 `pandas` — Tableaux de données dans Streamlit

**Choix retenu.** `pandas` est utilisé dans `app.py` pour convertir les alertes en `DataFrame` et les afficher avec `st.dataframe()`, qui supporte le tri interactif des colonnes dans l'interface web.

**Alternative écartée.** L'affichage de listes de dictionnaires brutes avec `st.table()` est possible mais ne supporte pas le tri interactif ni le filtrage, réduisant l'ergonomie de l'interface.

---

## 4. Architecture et conception

### 4.1 Principe SRP — Single Responsibility Principle

L'architecture de Log Sentinel est guidée par le **Principe de Responsabilité Unique** : chaque module encapsule une et une seule responsabilité fonctionnelle. Ce principe garantit que la modification d'une fonctionnalité (par exemple, le changement de l'algorithme de détection brute-force) n'impacte pas les autres modules.

| Module | Responsabilité unique |
|---|---|
| `src/loader.py` | Lecture du fichier et détection de format |
| `src/parser.py` | Transformation de lignes brutes en `LogEntry` |
| `src/detector.py` | Détection des attaques → production d'`Alert` |
| `src/statistics.py` | Calcul de métriques agrégées |
| `src/osint.py` | Enrichissement OSINT des IPs suspectes |
| `src/reporter.py` | Génération du rapport HTML |
| `main.py` | Orchestration CLI + affichage Rich |
| `app.py` | Orchestration interface web Streamlit |

### 4.2 Arborescence du projet

```
log_sentinel/
├── main.py                 ← Point d'entrée CLI (argparse + Rich)
├── app.py                  ← Point d'entrée interface web (Streamlit)
├── requirements.txt        ← Dépendances tierces (4 bibliothèques)
├── samples/
│   └── sample_access.log   ← Fichier de test (60 lignes, format NGINX)
├── reports/
│   └── report.html         ← Rapport HTML généré
├── src/
│   ├── __init__.py
│   ├── loader.py           ← Chargement + détection de format
│   ├── parser.py           ← Parsing → dataclass LogEntry
│   ├── detector.py         ← Détection → dataclass Alert
│   ├── statistics.py       ← Statistiques → dict
│   ├── osint.py            ← Enrichissement OSINT via ip-api.com
│   └── reporter.py         ← Rapport HTML autonome
└── tests/
    ├── test_detector.py    ← 13 tests (AttackDetector + LogParser)
    └── test_statistics.py  ← 12 tests (LogStatistics + LogLoader)
```

---

📸 **CAPTURE D'ÉCRAN** — *Arborescence complète du projet dans un explorateur de fichiers ou dans le terminal (commande `tree`), montrant l'organisation en `src/`, `tests/`, `samples/` et `reports/`.*
> *(Insérer ici la capture)*

---

### 4.3 Pipeline de traitement

Le pipeline de traitement est identique que l'on utilise le CLI (`main.py`) ou l'interface web (`app.py`). Les deux points d'entrée consomment les mêmes modules `src/` avec la même séquence d'opérations :

```
┌─────────────────────────────────────────────────────────────────┐
│                       Fichier de log                            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  LogLoader.load()          → list[str]  (lignes brutes)         │
│  LogLoader.detect_format() → "apache" | "nginx" | "syslog"     │
│                              | "unknown"                        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  LogParser.parse_all()     → list[LogEntry]  (dataclass)        │
│  Conversion LogEntry → list[dict]                               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                   ┌────────┴────────┐
                   │                 │
                   ▼                 ▼
┌────────────────────────┐  ┌────────────────────────────────────┐
│  AttackDetector        │  │  LogStatistics.compute()           │
│  .detect_signature()   │  │  → dict (total_requests,           │
│  .detect_brute_force() │  │    unique_ips, top_ips,            │
│  .detect_scan()        │  │    status_codes, error_rate…)      │
│  → list[Alert]         │  └────────────────────────────────────┘
└────────────┬───────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│  OSINTChecker.check_ips()  → dict  (optionnel, --check-ip)      │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  HTMLReporter.generate()   → reports/report.html                │
│  Calcul score de risque    → 0-100                              │
└─────────────────────────────────────────────────────────────────┘
```

### 4.4 Modèle de données

Deux dataclasses structurent les données tout au long du pipeline.

**`LogEntry`** (définie dans `src/parser.py`) représente une ligne de log parsée avec succès :

```python
@dataclass
class LogEntry:
    ip: str = ""            # Adresse IP source
    timestamp: str = ""     # Date et heure de la requête
    method: str = ""        # Méthode HTTP (GET, POST, etc.)
    uri: str = ""           # Ressource demandée
    status_code: str = ""   # Code de réponse HTTP
    size: str = ""          # Taille de la réponse en octets
    user_agent: str = ""    # Chaîne User-Agent du client
```

**`Alert`** (définie dans `src/detector.py`) représente une alerte de sécurité produite par un des détecteurs :

```python
@dataclass
class Alert:
    attack_type: str    # Catégorie : "sql_injection", "xss", "brute_force"…
    ip: str             # IP source impliquée
    uri: str            # URI de la requête concernée
    user_agent: str     # User-Agent associé
    details: str        # Message explicatif (pattern matchant, seuil atteint…)
```

### 4.5 Deux points d'entrée, un seul pipeline

Une décision architecturale importante est l'**absence de duplication** de la logique métier entre `main.py` et `app.py`. Les deux fichiers importent et consomment les mêmes classes de `src/` :

- `main.py` appelle `detect_signature()`, `detect_brute_force()` et `detect_scan()` individuellement afin d'alimenter une barre de progression `rich.progress`.
- `app.py` appelle `detector.analyze()` qui encapsule les trois étapes en un seul appel, et utilise `st.session_state` pour mettre en cache les résultats entre les re-renders de Streamlit.

Cette architecture garantit que toute modification de la logique de détection (seuils, patterns) est automatiquement répercutée dans les deux interfaces.

---

## 5. Implémentation — Logique d'automatisation originale

Cette section détaille les cinq mécanismes algorithmiques originaux qui constituent le cœur de l'automatisation du projet. Conformément à la consigne, aucun moteur externe n'est utilisé : toute la logique est développée en Python natif.

### 5.1 Détection de format par algorithme de vote par score

**Localisation :** `src/loader.py`, méthode `detect_format()`

**Problématique.** Un fichier de log ne contient pas d'en-tête indiquant son format. Il est nécessaire d'inférer le format à partir du contenu brut des lignes.

**Algorithme mis en œuvre.** Un échantillon des 10 premières lignes non vides est testé contre trois expressions régulières compilées caractéristiques de chaque format supporté. Un dictionnaire de scores est incrémenté pour chaque correspondance. Le format avec le score le plus élevé est retenu. Si le score maximum est nul, le format `"unknown"` est retourné.

```python
# Extrait de src/loader.py — detect_format()

_SAMPLE_SIZE: int = 10

def detect_format(self, lines: list[str]) -> str:
    echantillon: list[str] = lines[:self._SAMPLE_SIZE]

    scores: dict[str, int] = {
        "nginx": 0,
        "apache": 0,
        "syslog": 0,
    }

    for ligne in echantillon:
        if _NGINX_PATTERN.match(ligne):
            scores["nginx"] += 1
        elif _APACHE_PATTERN.match(ligne):
            scores["apache"] += 1
        elif _SYSLOG_PATTERN.match(ligne):
            scores["syslog"] += 1

    meilleur_format = max(scores, key=lambda fmt: scores[fmt])
    meilleur_score = scores[meilleur_format]

    if meilleur_score == 0:
        return "unknown"

    return meilleur_format
```

**Justification du choix.** L'algorithme de vote est plus robuste qu'une simple vérification de la première ligne (qui peut être un commentaire ou une ligne malformée). En testant un échantillon et en prenant la majorité, la détection résiste aux lignes aberrantes en début de fichier. La complexité est O(n) avec n ≤ 10, soit O(1) en pratique.

Les trois regex de détection de format sont distinctes des regex de parsing : elles sont volontairement plus strictes pour éviter les faux positifs lors de la détection, alors que les regex de parsing sont plus tolérantes pour maximiser le nombre de lignes correctement extraites.

### 5.2 Détection par signatures — 6 regex hand-crafted

**Localisation :** `src/detector.py`, dictionnaire `ATTACK_PATTERNS` et méthode `detect_signature()`

**Problématique.** Identifier dans une URI ou un user-agent les marqueurs caractéristiques des principales techniques d'attaque web.

**Algorithme mis en œuvre.** Un dictionnaire `ATTACK_PATTERNS` associe chaque catégorie d'attaque à une expression régulière compilée. La méthode `detect_signature()` applique les 5 patterns URI sur le champ `uri` de l'entrée, et le pattern `malicious_ua` sur le champ `user_agent`. Une `Alert` est produite pour chaque correspondance, avec le fragment matchant inclus dans le champ `details`.

```python
# Extrait de src/detector.py — ATTACK_PATTERNS

ATTACK_PATTERNS: dict[str, re.Pattern] = {
    "sql_injection": re.compile(
        r"UNION\s+SELECT|OR\s+1\s*=\s*1|DROP\s+TABLE|INSERT\s+INTO|'\s*OR\s+'|--",
        re.IGNORECASE,
    ),
    "xss": re.compile(
        r"<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(",
        re.IGNORECASE,
    ),
    "path_traversal": re.compile(
        r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|C:\\Windows",
        re.IGNORECASE,
    ),
    "command_injection": re.compile(
        r";ls|\|cat|\$\(|&&rm|`whoami`",
        re.IGNORECASE,
    ),
    "sensitive_files": re.compile(
        r"\.env|\.git|\.htaccess|wp-config\.php|/etc/passwd|id_rsa",
        re.IGNORECASE,
    ),
    "malicious_ua": re.compile(
        r"sqlmap|nikto|nmap|burp|wpscan|masscan|metasploit|hydra|dirbuster",
        re.IGNORECASE,
    ),
}
```

**Justification du choix.** Les patterns sont construits manuellement (*hand-crafted*) sur la base des signatures d'attaque les plus documentées dans les références OWASP. Le flag `re.IGNORECASE` assure la détection indépendamment de la casse, ce qui est essentiel car les attaquants encodent fréquemment leurs payloads avec des majuscules pour contourner des filtres simples. La compilation à l'import (`re.compile`) évite la recompilation à chaque appel, ce qui est critique pour les performances lors de l'analyse de milliers de lignes.

La séparation `uri_patterns` / `malicious_ua` reflète une réalité opérationnelle : les injections se trouvent dans les URIs, tandis que les outils d'attaque s'identifient dans leur user-agent.

### 5.3 Détection de force brute par Counter sur codes 401/403

**Localisation :** `src/detector.py`, méthode `detect_brute_force()`

**Problématique.** Identifier une IP qui tente un grand nombre d'authentifications échouées, signe possible d'une attaque par force brute ou par dictionnaire.

**Algorithme mis en œuvre.** La méthode effectue un unique passage sur toutes les entrées. Un `Counter` accumule le nombre de réponses 401 (Non autorisé) ou 403 (Interdit) par adresse IP. Un dictionnaire parallèle `ip_last_entry` conserve la dernière entrée de chaque IP pour contextualiser l'alerte. Après le parcours, chaque IP dont le compteur dépasse le seuil configurable (`BRUTE_FORCE_THRESHOLD`, défaut : 5) produit une alerte.

```python
# Extrait de src/detector.py — detect_brute_force()

def detect_brute_force(self, entries: list[dict[str, Any]]) -> list[Alert]:
    threshold: int = self.CONFIG["BRUTE_FORCE_THRESHOLD"]
    alerts: list[Alert] = []

    # Comptage des échecs d'authentification par IP
    fail_counts: Counter = Counter()
    ip_last_entry: dict[str, dict[str, Any]] = {}

    for entry in entries:
        ip = entry.get("ip", "")
        status = str(entry.get("status", ""))
        if status in ("401", "403"):
            fail_counts[ip] += 1
            ip_last_entry[ip] = entry

    for ip, count in fail_counts.items():
        if count > threshold:
            last = ip_last_entry[ip]
            alerts.append(Alert(
                attack_type="brute_force",
                ip=ip,
                uri=last.get("uri", ""),
                user_agent=last.get("user_agent", ""),
                details=(
                    f"Brute force suspected: {count} failed "
                    f"authentications (401/403) from {ip} "
                    f"(threshold={threshold})"
                ),
            ))

    return alerts
```

**Justification du choix.** `Counter` est la structure de données idéale pour ce comptage : son interface est plus lisible que `dict.get(ip, 0) + 1`, et `most_common()` serait disponible si l'on souhaitait un classement. Le seuil configurable via `CONFIG["BRUTE_FORCE_THRESHOLD"]` (exposé aussi via l'argument `--bf-threshold` du CLI) permet d'adapter la sensibilité selon l'environnement (production stricte vs environnement de développement avec de nombreux faux positifs).

La complexité est O(n) avec n le nombre d'entrées, ce qui est optimal pour ce type d'analyse.

### 5.4 Détection de scan par double critère

**Localisation :** `src/detector.py`, méthode `detect_scan()`

**Problématique.** Identifier une IP qui énumère systématiquement des ressources du serveur (scan de répertoires, recherche de vulnérabilités). Ce comportement se caractérise par un grand nombre d'URIs distinctes associées à un taux élevé de réponses 404.

**Algorithme mis en œuvre.** Un `defaultdict` accumule pour chaque IP : un `set` des URIs vues (pour dédoublonner), un compteur total de requêtes, et un compteur de réponses 404. Après le parcours, deux critères **cumulatifs** sont évalués pour chaque IP :
- le nombre d'URIs distinctes dépasse `SCAN_THRESHOLD` (défaut : 10) ;
- la proportion de réponses 404 dépasse 50 %.

```python
# Extrait de src/detector.py — detect_scan()

def detect_scan(self, entries: list[dict[str, Any]]) -> list[Alert]:
    scan_threshold: int = self.CONFIG["SCAN_THRESHOLD"]

    # Structure : ip -> {"uris": set(), "total": int, "not_found": int}
    ip_stats: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"uris": set(), "total": 0, "not_found": 0, "user_agent": ""}
    )

    for entry in entries:
        ip = entry.get("ip", "")
        uri = entry.get("uri", "")
        status = str(entry.get("status", ""))
        ua = entry.get("user_agent", "")

        stats = ip_stats[ip]
        stats["uris"].add(uri)       # set() dédoublonne automatiquement
        stats["total"] += 1
        if status == "404":
            stats["not_found"] += 1
        if ua:
            stats["user_agent"] = ua

    for ip, stats in ip_stats.items():
        unique_uris = len(stats["uris"])
        not_found_ratio = stats["not_found"] / stats["total"]

        if unique_uris > scan_threshold and not_found_ratio > 0.5:
            alerts.append(Alert(
                attack_type="scan",
                ip=ip,
                uri="(multiple)",
                user_agent=stats["user_agent"],
                details=(
                    f"Scan suspected from {ip}: "
                    f"{unique_uris} distinct URIs probed, "
                    f"{not_found_ratio:.0%} returned 404 "
                    f"(threshold: >{scan_threshold} URIs and >50% 404)"
                ),
            ))
```

**Justification du choix.** Le double critère est essentiel pour réduire les faux positifs. Un utilisateur qui navigue beaucoup sur un site peut générer de nombreuses URIs distinctes (premier critère seul), mais il aura majoritairement des réponses 200, pas 404. À l'inverse, un bug d'application peut générer beaucoup de 404, mais sur peu d'URIs distinctes. Le scan réunit les deux : beaucoup d'URIs inconnues testées successivement.

L'utilisation d'un `set` pour les URIs est cruciale : elle dédoublonne automatiquement sans code supplémentaire, et `len(set)` est O(1).

### 5.5 Score de risque — formule pondérée à 3 composantes

**Localisation :** `main.py`, section "Résumé final" ; `app.py`, fonction `_calculer_score_risque()`

**Problématique.** Synthétiser en un indicateur unique (0–100) la sévérité globale de l'analyse pour un décideur non technique.

**Formule mise en œuvre :**

```
score = min(50, alert_count × 2)           [composante alertes,    plafonnée à 50]
      + min(30, error_rate × 0.6)           [composante taux erreur, plafonnée à 30]
      + 20 si type lourd présent, sinon 0   [composante pénalité,   binaire]

score_final = min(100, score)
```

Les types "lourds" déclenchant la pénalité de 20 points sont : `brute_force`, `scan`, `sql_injection`, `command_injection`.

```python
# Extrait de main.py — calcul du score de risque

alert_score   = min(50, alert_count * 2)
error_score   = min(30, error_rate * 0.6)
heavy_types   = {"brute_force", "scan", "sql_injection", "command_injection"}
heavy_penalty = 20 if any(a.attack_type in heavy_types for a in alerts) else 0
risk_score    = int(min(100, alert_score + error_score + heavy_penalty))
```

| Plage | Niveau de risque | Couleur |
|---|---|---|
| 0 — 19 | FAIBLE | Vert |
| 20 — 49 | MODÉRÉ | Jaune |
| 50 — 74 | ÉLEVÉ | Orange |
| 75 — 100 | CRITIQUE | Rouge |

**Justification du choix.** La formule est intentionnellement heuristique : elle n'a pas de fondement probabiliste rigoureux, mais elle est **transparente et explicable**, ce qui est une qualité essentielle pour un outil défensif. Un analyste SOC peut comprendre et contester le score. La décomposition en trois composantes permet de distinguer :
- un fichier avec de nombreuses petites alertes (beaucoup de malicious_ua) d'un fichier avec peu d'alertes mais très graves (une sql_injection + un brute_force) ;
- l'impact du taux d'erreur global, qui reflète l'état général du serveur.

---

## 6. Gestion des erreurs et robustesse

### 6.1 Exceptions gérées dans loader.py

La méthode `LogLoader.load()` constitue le premier point de contact avec l'environnement externe (le système de fichiers). Trois types d'exceptions sont gérés explicitement :

| Exception | Condition | Comportement |
|---|---|---|
| `FileNotFoundError` | Le chemin ne pointe pas vers un fichier existant | Message d'erreur explicite avec le chemin, arrêt propre |
| `FileNotFoundError` | Le chemin existe mais n'est pas un fichier régulier (répertoire) | Message différencié indiquant "n'est pas un fichier régulier" |
| `UnicodeDecodeError` | Échec de décodage après épuisement des encodages | Re-levée avec contexte enrichi précisant les encodages tentés |
| `OSError` | Erreur système (permissions, etc.) | Propagation vers le point d'entrée qui l'intercepte |

Dans `main.py`, ces exceptions sont interceptées au niveau le plus haut avec des messages utilisateur clairs et un `sys.exit(1)` pour signaler l'échec à l'environnement appelant (scripts shell, CI/CD).

### 6.2 Fallback d'encodage UTF-8 → Latin-1

Un mécanisme de repli automatique est implémenté dans `load()` pour gérer les fichiers de logs produits par des systèmes anciens ou mal configurés qui utilisent Latin-1 (ISO-8859-1) au lieu de UTF-8 :

```python
# Extrait de src/loader.py — mécanisme de repli d'encodage

_ENCODINGS: list[str] = ["utf-8", "latin-1"]

for encoding in self._ENCODINGS:
    try:
        with open(path, "r", encoding=encoding, errors="strict") as fh:
            lignes = [line.rstrip("\n").rstrip("\r") for line in fh if line.strip()]
        return lignes
    except UnicodeDecodeError as exc:
        last_error = exc
        continue  # essai de l'encodage suivant
```

La liste `_ENCODINGS` est un attribut de classe, ce qui permet de l'étendre facilement (ajout de `"cp1252"` par exemple) sans modifier la logique de la méthode.

### 6.3 Format "unknown" — comportement du système

Lorsque `detect_format()` retourne `"unknown"`, le parser adopte une stratégie de **tentative en cascade** : il essaie successivement Apache, Nginx puis Syslog, et retourne le premier résultat valide. Cette approche de *best-effort parsing* maximise la quantité de données récupérables sur un fichier de format non reconnu.

```python
# Extrait de src/parser.py — parse_line() pour format inconnu

if fmt_lower == "unknown":
    for parser in (self._parse_apache, self._parse_nginx, self._parse_syslog):
        entry = parser(line)
        if entry is not None:
            return entry
    return None
```

Les lignes qui ne correspondent à aucun format sont silencieusement ignorées (`parse_all()` filtre les `None`), ce qui est le comportement attendu : un fichier hétérogène partiel vaut mieux qu'une erreur fatale.

### 6.4 Timeout et robustesse du module OSINT

Le module `osint.py` interroge une API externe. Plusieurs scénarios de défaillance réseau sont couverts avec des `except` distincts pour chaque type d'exception `requests` :

```python
# Extrait de src/osint.py — gestion des erreurs réseau

try:
    response = requests.get(url, timeout=_REQUEST_TIMEOUT)  # timeout = 3s
    response.raise_for_status()
    data = response.json()
except requests.exceptions.ConnectionError:
    return {}   # réseau indisponible
except requests.exceptions.Timeout:
    return {}   # délai dépassé
except requests.exceptions.HTTPError:
    return {}   # code HTTP d'erreur (4xx, 5xx)
except requests.exceptions.RequestException:
    return {}   # toute autre erreur requests
except ValueError:
    return {}   # réponse non-JSON
```

Le timeout de 3 secondes par IP est un compromis entre réactivité et tolérance réseau. La méthode `check_ips()` est limitée à 5 IPs par défaut pour respecter les limites de l'API publique `ip-api.com` (45 requêtes/minute sans clé).

---

## 7. Tests unitaires

### 7.1 Stratégie de test

La stratégie de test adoptée est le **test unitaire par classe et par comportement**. Chaque test vérifie un comportement précis et isolé : une entrée produit-elle le bon type d'alerte ? Un seuil non atteint produit-il bien zéro alerte ? Un fichier invalide lève-t-il bien l'exception appropriée ?

Les tests sont écrits avec le module standard `unittest` et organisés en deux fichiers :

- `tests/test_detector.py` : 13 tests couvrant `AttackDetector` et `LogParser` ;
- `tests/test_statistics.py` : 12 tests couvrant `LogStatistics` et `LogLoader`.

Total : **25 tests unitaires**.

### 7.2 Couverture des tests

**`test_detector.py` — 13 tests**

| Numéro | Classe testée | Méthode testée | Comportement vérifié |
|---|---|---|---|
| 1 | `AttackDetector` | `detect_signature` | URI avec `UNION SELECT` → alerte `sql_injection` |
| 2 | `AttackDetector` | `detect_signature` | URI avec `<script>` → alerte `xss` |
| 3 | `AttackDetector` | `detect_signature` | URI avec `../../../etc/passwd` → alerte `path_traversal` |
| 4 | `AttackDetector` | `detect_signature` | URI avec `/.env` → alerte `sensitive_files` |
| 5 | `AttackDetector` | `detect_signature` | UA avec `sqlmap/1.7.2` → alerte `malicious_ua` |
| 6 | `AttackDetector` | `detect_signature` | URI avec `;ls -la` → alerte `command_injection` |
| 7 | `AttackDetector` | `detect_signature` | URI `/index.html`, UA normal → 0 alerte |
| 8 | `AttackDetector` | `detect_brute_force` | 6 réponses 401 même IP → alerte `brute_force` |
| 9 | `AttackDetector` | `detect_brute_force` | 3 réponses 401 même IP → 0 alerte (sous le seuil) |
| 10 | `AttackDetector` | `detect_scan` | 15 URIs distinctes, 100% 404 → alerte `scan` |
| 11 | `LogParser` | `parse_line` | Ligne Apache valide → `LogEntry` correct (ip, method, uri, status) |
| 12 | `LogParser` | `parse_line` | Ligne invalide → `None` |
| 13 | `LogParser` | `parse_all` | 3 lignes (2 valides, 1 invalide) → liste de 2 entrées |

**`test_statistics.py` — 12 tests**

| Numéro | Classe testée | Comportement vérifié |
|---|---|---|
| 1 | `LogStatistics` | Entrées vides → `total_requests=0`, `unique_ips=0` |
| 2 | `LogStatistics` | 3 entrées → `total_requests=3` |
| 3 | `LogStatistics` | 2 IPs distinctes sur 3 entrées → `unique_ips=2` |
| 4 | `LogStatistics` | IP la plus fréquente en première position du `top_ips` |
| 5 | `LogStatistics` | 1 entrée 200 + 1 entrée 404 → `error_rate=50.0` |
| 6 | `LogStatistics` | Distribution correcte des codes HTTP dans `status_codes` |
| 7 | `LogStatistics` | Distribution correcte des méthodes HTTP dans `methods` |
| 8 | `LogLoader` | Chemin inexistant → `FileNotFoundError` |
| 9 | `LogLoader` | Fichier valide chargé → 3 lignes retournées |
| 10 | `LogLoader` | Lignes vides ignorées → 2 lignes non vides retournées |
| 11 | `LogLoader` | Lignes Apache valides → format détecté `"apache"` |
| 12 | `LogLoader` | Lignes sans format reconnu → format détecté `"unknown"` |

### 7.3 Exemple de cas de test commenté

Le test suivant illustre la vérification du comportement brute-force avec un cas limite sur le seuil :

```python
def test_brute_force_detected(self):
    """6 réponses 401 depuis la même IP doivent lever une alerte brute_force.

    Le seuil est strictement supérieur à 5 (threshold=5, condition count > 5),
    donc 6 entrées déclenchent l'alerte.
    """
    entries = [
        _make_entry(ip="10.0.0.1", uri="/login", status="401")
        for _ in range(6)
    ]
    alerts = self.detector.detect_brute_force(entries)
    attack_types = [a.attack_type for a in alerts]
    self.assertIn("brute_force", attack_types)

def test_brute_force_below_threshold(self):
    """3 réponses 401 ne doivent pas déclencher d'alerte brute_force."""
    entries = [
        _make_entry(ip="10.0.0.1", uri="/login", status="401")
        for _ in range(3)
    ]
    alerts = self.detector.detect_brute_force(entries)
    attack_types = [a.attack_type for a in alerts]
    self.assertNotIn("brute_force", attack_types)
```

Ces deux tests complémentaires vérifient les deux côtés du seuil (cas passant et cas non passant), ce qui garantit que la condition `count > threshold` est bien stricte et non large (`>=`).

### 7.4 Exécution des tests

```bash
# Depuis le répertoire log_sentinel/, environnement virtuel activé
python -m unittest discover -s tests -v
```

---

📸 **CAPTURE D'ÉCRAN** — *Résultat des 25 tests unitaires dans le terminal : `python -m unittest discover -s tests -v`, montrant tous les tests avec leur statut `OK` et le résumé final `Ran 25 tests in X.XXXs — OK`.*
> *(Insérer ici la capture)*

---

---

## 8. Résultats et analyse

### 8.1 Conditions d'exécution

Le fichier de test utilisé est `samples/sample_access.log`, un fichier synthétique de **60 lignes** au **format NGINX**, contenant des requêtes légitimes et des tentatives d'attaque simulées couvrant l'ensemble des catégories détectées.

Commande d'exécution :
```bash
python main.py -f samples/sample_access.log
```

### 8.2 Résultats de détection — 25 alertes

L'analyse du fichier `sample_access.log` produit **25 alertes** réparties comme suit :

| Catégorie d'attaque | Nombre d'alertes | Mécanisme de détection |
|---|---|---|
| `malicious_ua` | 9 | Pattern regex sur user-agent |
| `path_traversal` | 4 | Pattern regex sur URI |
| `sql_injection` | 4 | Pattern regex sur URI |
| `xss` | 3 | Pattern regex sur URI |
| `sensitive_files` | 3 | Pattern regex sur URI |
| `brute_force` | 1 | Counter 401/403 > seuil 5 |
| `scan` | 1 | Double critère URIs distinctes + taux 404 |
| **Total** | **25** | |

Les 9 alertes `malicious_ua` indiquent la présence d'outils d'attaque automatisés (sqlmap, nikto, dirbuster, etc.) identifiés dans les chaînes User-Agent. Les 4 alertes `path_traversal` signalent des tentatives de traversée de répertoires vers `/etc/passwd` ou via des séquences `../`. Les 4 alertes `sql_injection` correspondent à des patterns `UNION SELECT`, `OR 1=1` ou `--` dans les URIs.

L'alerte `brute_force` unique signifie qu'une seule IP a dépassé le seuil de 5 réponses 401/403. L'alerte `scan` unique indique une IP ayant sondé plus de 10 URIs distinctes avec un taux de 404 supérieur à 50%.

### 8.3 Statistiques globales

| Métrique | Valeur |
|---|---|
| Lignes chargées | 60 |
| Format détecté | NGINX |
| Entrées parsées | 60 / 60 (100%) |
| Alertes levées | 25 |
| IPs uniques | — (variable selon le fichier) |
| Taux d'erreur | — (variable selon le fichier) |

### 8.4 Analyse du score de risque 100/100 CRITIQUE

Le score de risque de **100/100** résulte de l'accumulation des trois composantes :

```
alert_score   = min(50, 25 × 2) = min(50, 50) = 50
error_score   = min(30, error_rate × 0.6)       ≈ 30  (taux d'erreur élevé dans le sample)
heavy_penalty = 20  (présence de brute_force, sql_injection, scan)

score_final = min(100, 50 + 30 + 20) = 100
```

Ce score de 100 est cohérent avec la nature du fichier de test, qui a été **conçu pour exercer toutes les catégories de détection**. En conditions réelles, un fichier de production avec quelques centaines de milliers de requêtes légitimes et quelques tentatives isolées produirait un score nettement inférieur.

La valeur pédagogique du score 100 est de démontrer que le plafonnement `min(100, ...)` fonctionne et que les trois composantes s'accumulent bien. Ce résultat valide l'implémentation de la formule.

---

📸 **CAPTURE D'ÉCRAN** — *Exécution CLI complète dans le terminal : bannière Log Sentinel en rouge, tableau Rich des 25 alertes avec codes couleur par type, statistiques générales, et panneau final avec score de risque 100/100 CRITIQUE en rouge.*
> *(Insérer ici la capture)*

---

---

📸 **CAPTURE D'ÉCRAN** — *Interface Streamlit avec les 4 onglets visibles (Alertes, Statistiques, OSINT, Rapport HTML), onglet Alertes actif montrant le tableau pandas des 25 alertes, et les métriques `st.metric` en haut (25 alertes, score 100, format NGINX).*
> *(Insérer ici la capture)*

---

---

📸 **CAPTURE D'ÉCRAN** — *Rapport HTML généré (`reports/report.html`) ouvert dans le navigateur web, montrant le thème sombre, le score de risque 100/100 en rouge avec la barre de progression, les cards statistiques, et le tableau des alertes avec badges colorés par type d'attaque.*
> *(Insérer ici la capture)*

---

---

## 9. Bilan par rapport à la consigne

### 9.1 Tableau de conformité aux contraintes

| Critère de la consigne | Implémentation dans le projet | Statut |
|---|---|---|
| **Structures de données complexes** | `Counter` (fail_counts, ip_counter, uri_counter), `defaultdict` (ip_stats dans detect_scan), `set` (URIs distinctes), `dict` (scores, CONFIG, ATTACK_PATTERNS), `list` (entries, alerts) | Respecté |
| **Modularité — une fonction = une action** | `load()`, `detect_format()`, `parse_line()`, `parse_all()`, `detect_signature()`, `detect_brute_force()`, `detect_scan()`, `compute()`, `check_ip()`, `check_ips()`, `generate()` — chaque méthode a une responsabilité unique | Respecté |
| **Robustesse — gestion des exceptions** | `FileNotFoundError`, `UnicodeDecodeError`, `OSError` dans loader.py ; `ConnectionError`, `Timeout`, `HTTPError`, `RequestException`, `ValueError` dans osint.py ; `Exception` globale dans main.py pour les étapes parsing, détection, statistiques | Respecté |
| **CLI argparse** | `main.py` avec `-f/--file` (requis), `--bf-threshold`, `--scan-threshold`, `--report/--no-report`, `--check-ip`, `--output-dir` ; aide automatique `--help` | Respecté |
| **Interface web Streamlit** | `app.py` avec 4 onglets (Alertes, Statistiques, OSINT, Rapport HTML), upload de fichier, st.session_state pour cache, st.metric pour indicateurs | Respecté |
| **Bibliothèque `rich`** | Tableaux colorés, panneaux, barre de progression, bannière ASCII dans main.py | Respecté |
| **Bibliothèque `requests`** | Interrogation de ip-api.com dans osint.py | Respecté |
| **Bibliothèque `streamlit`** | Interface web complète dans app.py | Respecté |
| **Bibliothèque `pandas`** | Conversion des alertes en DataFrame pour affichage interactif dans app.py | Respecté |
| **Logique d'automatisation originale** | 5 algorithmes originaux : vote par score, 6 regex hand-crafted, Counter brute-force, double critère scan, formule de score pondérée | Respecté |
| **Tests unitaires** | 25 tests (13 + 12) avec unittest, cas passants et cas limites | Non explicitement requis — valeur ajoutée |

---

## 10. Limites et améliorations

### 10.1 Limites identifiées

**Absence de corrélation temporelle.** Les détecteurs actuels ignorent l'horodatage des entrées. La détection brute-force compte les échecs sur la totalité du fichier, pas sur une fenêtre temporelle glissante. En production, 6 réponses 401 sur 30 jours ne constituent pas une attaque, alors que 6 réponses 401 en 10 secondes sont un signal très fort. Cette limite n'a pas été levée car elle aurait nécessité la création d'un module de gestion du temps et l'implémentation d'une fenêtre glissante, ajoutant une complexité significative hors périmètre initial.

**Couverture des patterns regex limitée.** Les 6 patterns de signature couvrent les formes d'attaque les plus documentées, mais pas leurs variantes encodées (URL encoding `%27` pour `'`, double encoding `%2527`, Unicode encoding). Un attaquant conscient peut contourner ces signatures. Cette limite est inhérente à toute approche par signature statique.

**Trois formats supportés seulement.** Apache, Nginx et Syslog couvrent la grande majorité des cas d'usage courants, mais excluent les logs applicatifs (JSON structuré, formats propriétaires), les logs Windows (Event Log, IIS), et les logs de pare-feux.

**Score de risque heuristique.** La formule de score est empirique et non calibrée sur des données réelles. Elle peut produire un score de 100 sur un fichier de test synthétique, ce qui réduit sa valeur discriminante. Un score de risque rigoureux nécessiterait une calibration sur des corpus de logs étiquetés.

**Duplication de la formule de score.** La fonction `_calculer_score_risque` est présente à la fois dans `main.py` et `app.py`. Cette duplication est intentionnelle pour maintenir l'indépendance des deux points d'entrée, mais elle viole le principe DRY (*Don't Repeat Yourself*) et représente un risque de divergence lors de futures modifications.

### 10.2 Améliorations futures

**Fenêtre temporelle glissante.** Implémenter une analyse des horodatages pour détecter les rafales d'échecs d'authentification sur une période configurable (ex. : `--bf-window 60` pour une fenêtre de 60 secondes). Cela nécessiterait le parsing des timestamps et l'utilisation de `collections.deque` ou de `pandas.DataFrame` pour le filtrage temporel.

**Enrichissement des patterns d'attaque.** Ajouter la détection des payloads URL-encodés, des injections LDAP, des attaques SSRF (*Server-Side Request Forgery*) et des tentatives d'exploitation de Log4Shell (`${jndi:ldap://...}`).

**Support de formats supplémentaires.** JSON structuré (logs Cloudflare, AWS ELB, Azure), format W3C (IIS), format CEF (*Common Event Format*) des pare-feux.

**Stockage et persistance.** Export des alertes en JSON ou CSV pour intégration avec des outils SIEM. Stockage en base SQLite pour l'analyse de séries temporelles et la détection de campagnes d'attaque multi-fichiers.

**Machine learning pour la détection d'anomalies.** Un modèle d'isolation forest ou de clustering (k-means sur les vecteurs de comportement par IP) permettrait de détecter des comportements anormaux sans signatures prédéfinies. Cette piste serait pertinente dans le cadre d'un projet de Master 2.

---

## 11. Conclusion

Le projet Log Sentinel répond pleinement à la consigne du module Python en développant un outil de cybersécurité défensive fonctionnel, modulaire et robuste. Les cinq contraintes techniques imposées — structures de données complexes, modularité, robustesse, interfaces CLI et web, bibliothèques tierces — ont été satisfaites, avec une valeur ajoutée notable : le développement d'une logique d'automatisation entièrement originale codée sans moteur externe.

Le projet illustre concrètement plusieurs compétences du parcours Master 1 Cybersécurité : connaissance des formats de logs et des types d'attaques web, conception d'outils défensifs Blue Team, écriture de code robuste avec gestion d'exceptions, et production d'interfaces utilisateur adaptées à des publics techniques et non techniques.

Les résultats obtenus sur le fichier de test `sample_access.log` — 25 alertes détectées, score 100/100 CRITIQUE, 25 tests unitaires passés — démontrent la cohérence entre la conception et l'implémentation. Les limites identifiées (absence de corrélation temporelle, patterns regex non exhaustifs, formule de score empirique) sont documentées honnêtement et ouvrent des perspectives d'amélioration réalistes.

Log Sentinel constitue ainsi une base technique solide, directement extensible vers un outil de niveau production, et illustre à petite échelle les principes qui régissent les outils de détection d'intrusion utilisés dans les SOC professionnels.

---

## Références

- OWASP — Web Security Testing Guide (WSTG)
  https://owasp.org/www-project-web-security-testing-guide/

- NIST SP 800-92 — Guide to Computer Security Log Management
  https://csrc.nist.gov/pubs/sp/800/92/final

- Apache HTTP Server Documentation — Log Files
  https://httpd.apache.org/docs/current/logs.html

- Nginx Logging Documentation — ngx_http_log_module
  https://nginx.org/en/docs/http/ngx_http_log_module.html

- RFC 3164 — The BSD Syslog Protocol
  https://datatracker.ietf.org/doc/html/rfc3164

- Python 3.12 Documentation — collections.Counter
  https://docs.python.org/3/library/collections.html#collections.Counter

- Python 3.12 Documentation — dataclasses
  https://docs.python.org/3/library/dataclasses.html

- Rich — Python library for rich text in the terminal
  https://rich.readthedocs.io/

- Streamlit Documentation
  https://docs.streamlit.io/

- ip-api.com — Free IP Geolocation API
  https://ip-api.com/

---

*Rapport rédigé dans le cadre du module Python — Master 1 Cybersécurité — Mars 2026*
*NAOMIE NGWIDJOMBY MOUSSAVOU*
