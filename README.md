# Log Sentinel — Analyseur Intelligent de Logs (Blue Team)

> Outil Python de cybersécurité défensive orienté **Blue Team** pour l'analyse automatique
> de fichiers de logs, la détection d'attaques et la génération de rapports HTML.
>
> **Deux interfaces disponibles :** CLI enrichie (Rich + argparse) et tableau de bord Web interactif (Streamlit).

---

## Présentation

**Log Sentinel** répond à une problématique concrète en cybersécurité :

> *Comment automatiser l'analyse de logs de sécurité afin de détecter rapidement
> des comportements suspects, tout en restant dans une implémentation Python
> modulaire, robuste et exploitable en entreprise ?*

L'outil charge un fichier de log, détecte automatiquement son format, analyse
chaque ligne et identifie plusieurs types d'attaques — le tout présenté dans
un tableau de bord terminal **Rich** et un **rapport HTML** autonome, ou via
une **interface web Streamlit** interactive.

---

## Fonctionnalités

| Fonctionnalité | Description |
|----------------|-------------|
| Détection de format | Apache, Nginx, Syslog — automatique |
| SQL Injection | `UNION SELECT`, `OR 1=1`, `DROP TABLE`... |
| XSS | `<script>`, `onerror=`, `javascript:`... |
| Path Traversal | `../../etc/passwd`, `/etc/shadow`... |
| Brute-Force | Seuil configurable de tentatives 401/403 |
| Scan de ressources | Détection d'exploration massive d'URIs |
| Fichiers sensibles | `.env`, `.git`, `wp-config.php`... |
| Command Injection | `;ls`, `$(`, `\|cat`... |
| Scanners connus | `sqlmap`, `nikto`, `nmap`, `burp`... |
| OSINT | Géolocalisation IP via `ip-api.com` |
| Rapport HTML | Dashboard complet, score de risque, dark theme |
| **Interface Web** | **Tableau de bord Streamlit interactif** |

---

## Architecture

```
log_sentinel/
├── main.py                  # Point d'entrée CLI (argparse + Rich)
├── app.py                   # Interface Web Streamlit (tableau de bord)
├── requirements.txt         # Dépendances Python
├── src/
│   ├── loader.py            # Chargement fichier + détection format
│   ├── parser.py            # Parsing lignes → LogEntry (dataclass)
│   ├── detector.py          # Détection attaques (signatures + seuils)
│   ├── statistics.py        # Statistiques (Top IPs, codes HTTP...)
│   ├── osint.py             # Vérification IP externe (ip-api.com)
│   └── reporter.py          # Génération rapport HTML autonome
├── tests/
│   ├── test_detector.py     # 13 tests unitaires (AttackDetector, LogParser)
│   └── test_statistics.py   # 12 tests unitaires (LogStatistics, LogLoader)
└── samples/
    └── sample_access.log    # Fichier de log de démonstration (60 lignes)
```

**Pipeline de traitement :**
`LogLoader` → `LogParser` → `AttackDetector` → `LogStatistics` → `HTMLReporter`

Les deux interfaces (`main.py` CLI et `app.py` Streamlit) partagent exactement les mêmes modules `src/` — seule la couche de présentation diffère.

---

## Installation

### Prérequis

- Python 3.10+
- pip

### Étapes

```bash
# 1. Cloner le dépôt
git clone https://github.com/Moussavou001/log_sentinel_projet-python.git
cd log_sentinel_projet-python/log_sentinel

# 2. Créer un environnement virtuel (recommandé)
python -m venv env
env\Scripts\activate        # Windows
# source env/bin/activate   # Linux / macOS

# 3. Installer les dépendances
pip install -r requirements.txt
```

### Dépendances (`requirements.txt`)

```
requests>=2.31.0   # Requêtes HTTP (OSINT)
rich>=13.7.0       # Interface terminal colorée
streamlit>=1.32.0  # Interface Web interactive
pandas>=2.0.0      # Tableaux de données (interface web)
```

---

## Utilisation

### Interface Web (Streamlit) — Recommandée pour la démonstration

```bash
# Depuis le dossier log_sentinel/
streamlit run app.py
```

Le tableau de bord s'ouvre automatiquement dans le navigateur (`http://localhost:8501`).

#### Fonctionnalités de l'interface web

- **Barre latérale (sidebar) :** seuils brute-force et scan configurables, activation OSINT
- **Zone d'upload :** glisser-déposer ou sélection d'un fichier `.log` / `.txt`
- **Bouton "Utiliser le fichier démo" :** charge `samples/sample_access.log` directement
- **Onglet Alertes :** tableau filtrable par type d'attaque, badges colorés par catégorie
- **Onglet Statistiques :** graphiques interactifs (Top IPs, codes HTTP, URIs, méthodes)
- **Onglet OSINT :** géolocalisation IP (pays, ville, FAI, indicateur proxy)
- **Onglet Rapport HTML :** génération, aperçu inline et téléchargement en un clic

> **Note :** Les paramètres de la sidebar sont réactifs — modifier un seuil après une analyse
> réinitialise automatiquement les résultats via le mécanisme `session_state` de Streamlit,
> évitant d'afficher des résultats incohérents.

---

### Interface CLI (ligne de commande)

#### Commande de base

```bash
python main.py -f samples/sample_access.log
```

#### Toutes les options

```bash
python main.py -f <fichier_log> [OPTIONS]

Options :
  -f, --file           Chemin vers le fichier de log (obligatoire)
  --bf-threshold INT   Seuil de détection brute-force (défaut : 5)
  --scan-threshold INT Seuil de détection scan (défaut : 10)
  --report             Générer le rapport HTML (défaut : activé)
  --no-report          Désactiver la génération du rapport HTML
  --check-ip           Activer la vérification OSINT des IPs suspectes
  --output-dir DIR     Dossier de sortie pour le rapport (défaut : reports/)
```

#### Exemples

```bash
# Analyse standard
python main.py -f samples/sample_access.log

# Avec OSINT (géolocalisation des IPs suspectes)
python main.py -f samples/sample_access.log --check-ip

# Seuil brute-force personnalisé (alerte dès 3 tentatives)
python main.py -f samples/sample_access.log --bf-threshold 3

# Seuils combinés
python main.py -f samples/sample_access.log --bf-threshold 3 --scan-threshold 5

# Sans rapport HTML
python main.py -f samples/sample_access.log --no-report

# Rapport dans un dossier personnalisé
python main.py -f samples/sample_access.log --output-dir ./resultats_demo

# Toutes les options combinées
python main.py -f samples/sample_access.log --check-ip --bf-threshold 3 --scan-threshold 5 --output-dir ./resultats_demo
```

---

## Logique d'automatisation originale

> *La consigne exigeait "coder votre propre logique d'automatisation" — voici exactement ce qui
> a été codé from scratch, sans aucune bibliothèque de détection externe.*

### 1. Détection de format automatique (`loader.py`)

Algorithme de **vote par score** sur les 10 premières lignes du fichier :

```python
scores = {"nginx": 0, "apache": 0, "syslog": 0}
for ligne in echantillon:
    if _NGINX_PATTERN.match(ligne):    scores["nginx"]  += 1
    elif _APACHE_PATTERN.match(ligne): scores["apache"] += 1
    elif _SYSLOG_PATTERN.match(ligne): scores["syslog"] += 1
return max(scores, key=lambda fmt: scores[fmt])  # format gagnant
```

### 2. Détection d'attaques par signatures (`detector.py`)

6 patterns regex compilés à la main, appliqués sur l'URI ou le User-Agent selon le type :

```python
ATTACK_PATTERNS = {
    "sql_injection":     re.compile(r"UNION\s+SELECT|OR\s+1\s*=\s*1|DROP\s+TABLE..."),
    "xss":               re.compile(r"<script|javascript:|onerror\s*=..."),
    "path_traversal":    re.compile(r"\.\./|/etc/passwd|/etc/shadow..."),
    "command_injection": re.compile(r";ls|\|cat|\$\(|&&rm..."),
    "sensitive_files":   re.compile(r"\.env|\.git|wp-config\.php..."),
    "malicious_ua":      re.compile(r"sqlmap|nikto|nmap|burp..."),
}
```

### 3. Détection brute-force par seuil (`detector.py`)

```python
# Comptage des échecs 401/403 par IP — logique 100% personnalisée
fail_counts: Counter = Counter()
for entry in entries:
    if str(entry["status"]) in ("401", "403"):
        fail_counts[entry["ip"]] += 1
# Alerte si le seuil configurable est dépassé
for ip, count in fail_counts.items():
    if count > self.CONFIG["BRUTE_FORCE_THRESHOLD"]:
        # → Alert brute_force
```

### 4. Détection de scan — double critère combiné (`detector.py`)

```python
# Double critère : évite les faux positifs sur les crawlers légitimes
if unique_uris > scan_threshold and not_found_ratio > 0.5:
    # → Alert scan
```

> Un crawler légitime très actif ne génère pas 50 % de 404 — ce double critère
> est la clé pour distinguer un scan malveillant d'une indexation normale.

### 5. Score de risque — formule pondérée (`main.py` et `app.py`)

```python
alert_score   = min(50, alert_count * 2)        # plafonné à 50
error_score   = min(30, error_rate * 0.6)        # plafonné à 30
heavy_penalty = 20 if attaques_graves else 0     # brute_force, scan, sql_injection, command_injection
risk_score    = min(100, alert_score + error_score + heavy_penalty)
```

---

## Exemple de résultat

### Terminal (Rich)

```
+-----------------------------------------------------------------------------+
|   _                  _____            _   _            _                    |
|  | |    ___   __ _  / ____|          | | (_)          | |                   |
|  | |   / _ \ / _` | \___  \  ___ _ __ | |_ _ _ __   ___|                   |
|  | |__| (_) | (_| |  ___) |/ _ \ '_ \| __| | '_ \ / _ \|                   |
|  |_____\___/ \__, | |____/ \  __/ | | | |_| | | | |  __/|                   |
|              |___/                                                          |
|    Blue Team Security Analyzer  |  v1.0.0                                   |
+-----------------------------------------------------------------------------+

 Fichier chargé : samples/sample_access.log
 Lignes lues    : 60
 Format détecté : NGINX

 Analyse terminée. 25 alerte(s) détectée(s).

+------+-------------------+------------------+--------------------------------+
| #    | Type              | IP               | URI                            |
+------+-------------------+------------------+--------------------------------+
|  1   | sql_injection     | 185.220.101.34   | /products?id=1+UNION+SELECT... |
|  2   | sql_injection     | 185.220.101.34   | /search?q=1'+OR+1=1--          |
|  5   | xss               | 91.108.4.201     | /search?q=<script>alert(1)...  |
|  8   | path_traversal    | 45.33.32.156     | /download?file=../../etc/pass  |
| 12   | sensitive_files   | 77.88.55.242     | /.env                          |
| 15   | malicious_ua      | 185.220.101.9    | /index.php?id=1                |
| 24   | brute_force       | 192.168.1.100    | /login                         |
| 25   | scan              | 10.0.0.55        | (multiple)                     |
+------+-------------------+------------------+--------------------------------+

 Score de risque : 100/100 — CRITIQUE
 Rapport HTML    : reports/report.html
```

### Tableau des 25 alertes (fichier démo)

| Type | Occurrences | Détail |
|------|------------|--------|
| `sql_injection` | 4 | Patterns `UNION`, `OR 1=1`, etc. dans l'URI |
| `xss` | 3 | Balises `<script>` encodées dans les paramètres |
| `path_traversal` | 4 | Séquences `../` pour sortir de la racine web |
| `sensitive_files` | 3 | Accès à `.env`, `wp-config.php`, `/.git/` |
| `malicious_ua` | 9 | User-Agents de scanners connus (sqlmap, Nikto...) |
| `brute_force` | 1 | IP `192.168.1.100` — seuil de 5 échecs dépassé |
| `scan` | 1 | IP `10.0.0.55` — 10+ URIs distinctes avec >50% de 404 |

### Rapport HTML

Le rapport HTML généré contient :
- **Score de risque global** (0–100) avec code couleur (vert / orange / rouge)
- **Tableau complet des alertes** avec badge par type d'attaque
- **Top 10 IPs** les plus actives
- **Distribution des codes HTTP** (2xx, 3xx, 4xx, 5xx)
- **Top URIs** ciblées
- **Données OSINT** (pays, ville, ISP) si `--check-ip` activé

---

## Tests unitaires

```bash
python -m unittest discover -s tests -v
```

Résultat attendu : **25 tests — OK**

```
test_brute_force_detection ............................ ok
test_brute_force_no_alert_below_threshold ............. ok
test_detect_signature_clean_entry ..................... ok
test_detect_signature_sql_injection ................... ok
test_detect_signature_xss ............................. ok
test_detect_signature_path_traversal .................. ok
test_detect_signature_sensitive_files ................. ok
test_detect_signature_malicious_ua .................... ok
test_detect_scan_detection ............................ ok
test_detect_scan_no_alert_below_threshold ............. ok
test_parser_apache_valid_line ......................... ok
test_parser_invalid_line .............................. ok
test_parser_nginx_valid_line .......................... ok
test_statistics_basic ................................. ok
test_statistics_empty ................................. ok
test_statistics_error_rate ............................ ok
test_statistics_methods ............................... ok
test_statistics_status_codes .......................... ok
test_statistics_top_ips ............................... ok
test_statistics_top_uris .............................. ok
test_statistics_unique_ips ............................ ok
test_loader_detect_format_nginx ....................... ok
test_loader_detect_format_unknown ..................... ok
test_loader_load_valid_file ........................... ok
test_loader_load_nonexistent_file ..................... ok

----------------------------------------------------------------------
Ran 25 tests in X.XXXs

OK
```

**Couverture :**
- `test_detector.py` — 13 tests sur `AttackDetector` et `LogParser` : chaque type d'attaque est testé avec des entrées valides et invalides pour vérifier l'absence de faux positifs.
- `test_statistics.py` — 12 tests sur `LogStatistics` et `LogLoader` : calcul des métriques avec des jeux de données contrôlés.

---

## Formats de logs supportés

| Format | Exemple |
|--------|---------|
| **Apache** Combined | `127.0.0.1 - - [28/Mar/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla"` |
| **Nginx** access log | Identique à Apache Combined |
| **Syslog** (RFC 3164) | `Mar 28 12:00:00 hostname sshd: Failed password for root` |

---

## Concepts techniques clés

| Concept | Usage dans le projet |
|---------|---------------------|
| `dataclass` | `LogEntry`, `Alert` — structures de données typées |
| `re.compile()` | Patterns d'attaque pré-compilés (performance) |
| `collections.Counter` | Comptage IPs, codes HTTP, méthodes |
| `defaultdict` | Accumulation des entrées par IP |
| `set` | Unicité des URIs pour détection de scan |
| `argparse` | Interface CLI professionnelle |
| `rich` | Tableaux et panels colorés dans le terminal |
| `requests` | Requêtes OSINT vers `ip-api.com` |
| `streamlit` | Interface web sans HTML/CSS/JS |
| `session_state` | Persistance des résultats entre les rerenders Streamlit |
| `tempfile` | Fichier temporaire pour uniformiser les sources d'entrée (upload vs disque) |

---

## Questions & Réponses techniques

### Architecture

**Q : Pourquoi avoir séparé CLI (`main.py`) et interface web (`app.py`) ?**

> Le principe SRP (Single Responsibility Principle) impose qu'un module ait une seule raison
> de changer. `main.py` orchestre la sortie terminal avec Rich et argparse ; `app.py` orchestre
> l'interface Streamlit avec `session_state`. Les deux partagent exactement le même pipeline
> `src/`, ce qui évite toute duplication de logique métier. Changer le moteur de détection
> ne touche que `detector.py`, sans impacter les deux interfaces.

**Q : Pourquoi avoir choisi Streamlit plutôt que Flask ou Django ?**

> Streamlit est conçu pour des applications data/analyse en Python pur. Il n'y a pas de
> HTML/CSS/JavaScript à écrire : chaque widget correspond à un appel de fonction Python.
> Pour un projet d'analyse de logs orienté cybersécurité, c'est le bon outil : rapide à
> développer, lisible, et professionnel sans sur-ingénierie.

### Détection

**Q : Comment fonctionne la détection de brute-force ?**

> Dans `detector.py`, `detect_brute_force()` itère sur toutes les entrées et compte,
> par IP, le nombre de réponses 401 ou 403. Si ce compteur dépasse `BRUTE_FORCE_THRESHOLD`
> (défaut 5, configurable via `--bf-threshold`), une alerte `brute_force` est générée avec
> l'IP incriminée et le nombre d'échecs constatés.

**Q : Comment garantir l'absence de faux positifs ?**

> Deux mécanismes : les patterns de signatures dans `detector.py` sont volontairement précis
> (`UNION SELECT`, `<script`, `../../../` — pas de mots génériques). La détection comportementale
> exige un cumul de conditions : pour le scan, il faut dépasser le seuil d'URIs **et** avoir
> un taux de 404 > 50 %, ce qui évite de signaler des crawlers légitimes très actifs.

**Q : Que se passe-t-il si le fichier de log a un format inconnu ?**

> `detect_format()` retourne `"unknown"`. `LogParser` tente alors tous les parseurs en séquence.
> Les lignes non parsables sont ignorées et le programme continue avec les entrées valides,
> en signalant le nombre de lignes traitées par rapport au total.

### Interface web

**Q : Comment fonctionne le `session_state` et pourquoi est-il nécessaire ?**

> Streamlit re-exécute tout le script Python à chaque interaction utilisateur.
> Sans `session_state`, les résultats seraient perdus à chaque clic. Une clé
> `derniere_cle_params` détecte si les seuils ont changé et réinitialise les
> résultats pour forcer une nouvelle analyse cohérente.

**Q : Quelle est la différence entre l'upload et le bouton "fichier démo" ?**

> Les deux alimentent le même pipeline `_executer_pipeline()`. L'upload lit depuis
> l'objet `UploadedFile` Streamlit (mémoire), le démo lit depuis `Path.read_text()`.
> Dans les deux cas, le contenu est écrit dans un `tempfile.NamedTemporaryFile` pour
> que `LogLoader` puisse le traiter de façon uniforme, puis ce fichier est supprimé.

### OSINT

**Q : L'API ip-api.com est-elle fiable en production ?**

> ip-api.com est gratuite, sans clé, mais limitée à 45 req/min et aux usages non commerciaux.
> Pour une démonstration, elle est suffisante. En production, on lui préférerait MaxMind GeoIP2
> (base locale, sans dépendance réseau) ou IPinfo.io pour des garanties de disponibilité,
> précision et conformité RGPD.

**Q : Pourquoi l'OSINT est-il limité à 5 IPs ?**

> Pour rester dans les limites de l'API gratuite (45 req/min). Ce choix est configurable
> dans `OSINTChecker.check_ips(max_ips=5)`. En production, on utiliserait une API payante
> ou AbuseIPDB avec authentification.

---

## Guide de démonstration rapide

### Checklist avant la soutenance

- [ ] Environnement virtuel activé
- [ ] Terminal ouvert dans `log_sentinel/`
- [ ] Fichier `samples/sample_access.log` présent
- [ ] Connexion Internet disponible (pour OSINT)
- [ ] Streamlit déjà lancé ou prêt (`streamlit run app.py`)

### Chrono CLI (10 min)

| Temps | Durée | Action |
|:-----:|:-----:|--------|
| 0 min | 1 min | Arborescence + architecture modulaire + principe SRP |
| 1 min | 3 min | `python main.py -f samples/sample_access.log` — commenter chaque section |
| 4 min | 1 min 30 | `--check-ip` — enrichissement OSINT des IPs suspectes |
| 5 min 30 | 1 min 30 | `--bf-threshold 3 --scan-threshold 5 --no-report --output-dir` |
| 7 min | 1 min | `python -m unittest discover -s tests -v` — 25/25 OK |
| 8 min | 2 min | Questions jury |

### Chrono Interface Web (10 min)

| Etape | Action | Durée |
|:-----:|--------|:-----:|
| 1 | `streamlit run app.py` + ouverture navigateur | 30 s |
| 2 | Présentation sidebar et zone upload | 1 min |
| 3 | Clic démo, métriques, score 100/100 CRITIQUE | 2 min |
| 4 | Onglet Alertes — filtres multiselect, badges colorés | 2 min |
| 5 | Onglet Statistiques — graphiques, dataframes | 2 min |
| 6 | Onglet OSINT — activer sidebar si Internet disponible | 1 min |
| 7 | Onglet Rapport — génération + téléchargement + aperçu | 1 min |

---

## Avertissement

> Cet outil est destiné à l'analyse de logs sur des systèmes dont vous êtes
> propriétaire ou pour lesquels vous disposez d'une autorisation explicite.
> Toute utilisation à des fins malveillantes est illégale et contraire à
> l'éthique professionnelle.

---

## Auteur

| Champ | Détail |
|-------|--------|
| **Nom** | NAOMIE NGWIDJOMBY MOUSSAVOU |
| **Module** | Python / Master 1 Cybersécurité |
| **Thème** | Analyse de Logs / Blue Team |
| **Date de remise** | 1 avril 2026 |
