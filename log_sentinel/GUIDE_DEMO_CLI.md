# Guide de Démonstration CLI — Log Sentinel

**Auteur :** NAOMIE NGWIDJOMBY MOUSSAVOU
**Module :** Projet de fin de module Python — Master 1 Cybersécurité
**Date de remise :** 1 avril 2026

---

## Checklist avant la démo

Effectuer ces vérifications **avant** d'entrer en salle de soutenance.

- [ ] Terminal ouvert dans le bon répertoire : `D:\Python\log_sentinel_projet-python\log_sentinel`
- [ ] Environnement virtuel activé
- [ ] Fichier de démo présent : `samples/sample_access.log`
- [ ] Connexion internet disponible (pour l'étape OSINT)
- [ ] Police du terminal suffisamment grande pour être lisible par le jury
- [ ] Dossier `reports/` vide ou absent (pour une génération propre en direct)

```bash
# Activation de l'environnement virtuel (PowerShell)
D:\Python\env\Scripts\activate

# Vérification du répertoire courant
cd D:\Python\log_sentinel_projet-python\log_sentinel
```

---

## Étape 1 — Présentation du projet (1 min)

### Ce qu'on dit au jury

> "Log Sentinel est un analyseur de logs de sécurité orienté Blue Team.
> Il détecte automatiquement les attaques courantes dans les fichiers de logs HTTP
> et génère un rapport HTML exploitable. Le projet est écrit entièrement en Python
> et respecte le principe de responsabilité unique (SRP) : chaque module a un rôle précis."

### Montrer l'arborescence

```bash
# Dans le terminal, afficher l'arborescence du projet
ls -R .
```

### Architecture modulaire à expliquer

```
log_sentinel/
├── main.py          ← Point d'entrée CLI (argparse + Rich)
├── app.py           ← Interface web Streamlit (hors périmètre de cette démo)
├── samples/
│   └── sample_access.log   ← Fichier de démonstration
├── reports/         ← Rapports HTML générés automatiquement
├── tests/
│   ├── test_detector.py    ← 13 tests (AttackDetector + LogParser)
│   └── test_statistics.py  ← 12 tests (LogStatistics + LogLoader)
└── src/
    ├── loader.py    ← Lecture du fichier + détection de format
    ├── parser.py    ← Parsing des lignes en objets LogEntry
    ├── detector.py  ← Détection des attaques par signatures + comportement
    ├── statistics.py← Calcul des métriques (top IPs, codes HTTP, méthodes...)
    ├── osint.py     ← Enrichissement géographique via ip-api.com
    └── reporter.py  ← Génération du rapport HTML autonome
```

**Pipeline de traitement :**
`LogLoader` → `LogParser` → `AttackDetector` → `LogStatistics` → `HTMLReporter`

---

## Étape 2 — Analyse standard (3 min)

### Commande à taper

```bash
python main.py -f samples/sample_access.log
```

### Commentaire section par section

#### Section Chargement
La sortie affiche :
```
Fichier chargé : samples/sample_access.log
Lignes lues    : 60
Format détecté : NGINX
```
> "Le module `loader.py` lit le fichier avec un mécanisme de fallback d'encodage,
> puis identifie le format par échantillonnage de lignes sur des expressions régulières.
> Ici, 60 lignes sont lues et le format NGINX est reconnu automatiquement."

#### Section Parsing
```
Entrées parsées : 60 / 60 lignes
```
> "Le module `parser.py` transforme chaque ligne brute en un objet structuré `LogEntry`
> (dataclass Python). Apache et NGINX partagent la même regex Combined Log Format.
> Toutes les 60 lignes ont été parsées avec succès."

#### Section Détection
```
Analyse terminée. 25 alerte(s) détectée(s).
```
> "Le module `detector.py` applique deux stratégies :
> - La détection par **signatures** : des regex pré-compilées analysent l'URI et le User-Agent
>   de chaque requête pour identifier SQL Injection, XSS, Path Traversal, etc.
> - La détection **comportementale** : brute-force (comptage des 401/403 par IP)
>   et scan de ports (nombre d'URIs distinctes avec taux de 404 élevé)."

#### Section Alertes
Le tableau affiche les 25 alertes :

| Type | Occurrences | Détail |
|------|------------|--------|
| `sql_injection` | 4 | Patterns `UNION`, `OR 1=1`, etc. dans l'URI |
| `xss` | 3 | Balises `<script>` encodées dans les paramètres |
| `path_traversal` | 4 | Séquences `../` pour sortir de la racine web |
| `sensitive_files` | 3 | Accès à `.env`, `wp-config.php`, `/.git/` |
| `malicious_ua` | 9 | User-Agents de scanners connus (sqlmap, Nikto...) |
| `brute_force` | 1 | IP `192.168.1.100` — seuil de 5 échecs dépassé |
| `scan` | 1 | IP `10.0.0.55` — 10+ URIs distinctes avec >50% de 404 |

> "Chaque alerte porte l'IP source, l'URI concernée et un message de détail.
> Le code couleur Rich permet d'identifier visuellement la criticité de chaque type d'attaque."

#### Section Statistiques
> "Le module `statistics.py` utilise `collections.Counter` et `defaultdict`
> pour calculer les métriques : top 5 des IPs les plus actives, distribution
> des codes HTTP, top URIs et méthodes HTTP utilisées."

#### Section Résumé final
```
Score de risque : 100/100 — CRITIQUE
Rapport HTML   : reports/report.html
```
> "Le score de risque est calculé selon une formule à trois composantes :
> - Jusqu'à 50 points pour le nombre d'alertes (2 points par alerte, plafonné)
> - Jusqu'à 30 points pour le taux d'erreur HTTP
> - 20 points de pénalité si des attaques graves sont présentes (brute_force, scan, sql_injection, command_injection)
>
> Ici, 25 alertes × 2 = 50 points + taux d'erreur + pénalité grave = **100/100 CRITIQUE**."

---

## Étape 3 — Option OSINT (1 min 30)

### Commande à taper

```bash
python main.py -f samples/sample_access.log --check-ip
```

### Ce qu'on dit au jury

> "L'option `--check-ip` active l'enrichissement OSINT des IPs suspectes.
> Le module `osint.py` extrait les IPs impliquées dans des alertes,
> puis interroge l'API publique **ip-api.com** en mode batch (jusqu'à 5 IPs, sans clé API).
>
> Pour chaque IP, on récupère : pays, ville, fournisseur d'accès (FAI),
> et un indicateur de proxy/VPN.
> Ces informations permettent à un analyste d'évaluer rapidement si une IP
> appartient à un hébergeur suspect, un pays à risque ou un service d'anonymisation."

### Résultat attendu dans le tableau OSINT

Le tableau affichera les colonnes : **IP / Pays / Ville / FAI / Proxy**

> "Dans un contexte réel, si une IP est identifiée comme proxy ou provient
> d'un pays inhabituellement actif, cela justifie un blocage immédiat
> au niveau du pare-feu ou une remontée d'incident."

---

## Étape 4 — Options avancées (1 min 30)

### Ajuster les seuils de détection comportementale

```bash
# Seuil brute-force abaissé à 3 tentatives, scan à 5 URIs distinctes
python main.py -f samples/sample_access.log --bf-threshold 3 --scan-threshold 5
```

> "En abaissant `--bf-threshold` de 5 à 3, on devient plus sensible
> aux tentatives de brute-force discrètes. En milieu de production,
> ce seuil s'adapte au profil de l'application surveillée."

### Désactiver la génération du rapport HTML

```bash
python main.py -f samples/sample_access.log --no-report
```

> "Par défaut, le rapport HTML est généré automatiquement.
> L'option `--no-report` est utile pour une analyse rapide en ligne de commande,
> sans écriture sur le disque."

### Changer le dossier de sortie

```bash
python main.py -f samples/sample_access.log --output-dir ./resultats_demo
```

> "L'option `--output-dir` permet de rediriger le rapport vers un dossier spécifique,
> pratique pour organiser les analyses par date ou par client."

### Combiner plusieurs options

```bash
python main.py -f samples/sample_access.log --check-ip --bf-threshold 3 --scan-threshold 5 --output-dir ./resultats_demo
```

---

## Étape 5 — Tests unitaires (1 min)

### Commande à taper

```bash
python -m unittest discover -s tests -v
```

### Résultat attendu

```
test_brute_force_detection ... ok
test_brute_force_no_alert_below_threshold ... ok
test_detect_signature_clean_entry ... ok
test_detect_signature_sql_injection ... ok
test_detect_signature_xss ... ok
test_detect_signature_path_traversal ... ok
test_detect_signature_sensitive_files ... ok
test_detect_signature_malicious_ua ... ok
test_detect_scan_detection ... ok
test_detect_scan_no_alert_below_threshold ... ok
test_parser_apache_valid_line ... ok
test_parser_invalid_line ... ok
test_parser_nginx_valid_line ... ok
test_statistics_basic ... ok
test_statistics_empty ... ok
test_statistics_error_rate ... ok
test_statistics_methods ... ok
test_statistics_status_codes ... ok
test_statistics_top_ips ... ok
test_statistics_top_uris ... ok
test_statistics_unique_ips ... ok
test_loader_detect_format_nginx ... ok
test_loader_detect_format_unknown ... ok
test_loader_load_valid_file ... ok
test_loader_load_nonexistent_file ... ok

----------------------------------------------------------------------
Ran 25 tests in X.XXXs

OK
```

> "La suite de tests couvre les deux modules critiques :
> - `test_detector.py` : 13 tests sur `AttackDetector` et `LogParser`
>   — chaque type d'attaque est testé individuellement avec des entrées
>   valides et invalides pour vérifier qu'il n'y a pas de faux positifs.
> - `test_statistics.py` : 12 tests sur `LogStatistics` et `LogLoader`
>   — on vérifie le calcul des métriques avec des jeux de données contrôlés."

---

## Questions jury — Réponses préparées

**Q1 : Pourquoi avoir séparé CLI (`main.py`) et interface web (`app.py`) ?**

> Le principe de responsabilité unique (SRP) impose qu'un module ait une seule raison de changer.
> `main.py` orchestre la sortie terminal avec Rich et argparse ; `app.py` orchestre
> l'interface Streamlit avec `st.session_state`. Les deux partagent exactement
> le même pipeline `src/`, ce qui évite la duplication de logique métier.
> Changer le moteur de détection ne touche que `detector.py`, sans impacter les interfaces.

---

**Q2 : Comment fonctionne la détection de brute-force ?**

> Dans `detector.py`, la méthode `detect_brute_force()` itère sur toutes les entrées
> et compte, par IP, le nombre de réponses avec code HTTP 401 ou 403.
> Si ce compteur dépasse `BRUTE_FORCE_THRESHOLD` (par défaut 5, configurable via `--bf-threshold`),
> une alerte `brute_force` est générée avec l'IP incriminée et le nombre d'échecs constatés.

---

**Q3 : Pourquoi utiliser des dataclasses pour `LogEntry` et `Alert` ?**

> Les dataclasses Python offrent trois avantages concrets ici :
> typage explicite des champs (lisibilité et maintenabilité),
> génération automatique de `__repr__` (facilite le débogage et les tests),
> et immutabilité possible avec `frozen=True`. Par rapport à de simples dictionnaires,
> on évite les erreurs de clé manquante au profit d'erreurs d'attribut détectées plus tôt.

---

**Q4 : L'API ip-api.com est-elle fiable en production ?**

> ip-api.com est une API publique, gratuite, sans clé, limitée à 45 requêtes/minute
> et à des usages non commerciaux. Pour une démonstration ou un outil interne,
> elle est suffisante. En production, on lui préférerait MaxMind GeoIP2 (base locale,
> sans dépendance réseau) ou une API commerciale comme IPinfo.io pour des garanties
> de disponibilité, de précision et de conformité RGPD.

---

**Q5 : Que se passe-t-il si le fichier de log a un format inconnu ?**

> Dans `loader.py`, la méthode `detect_format()` échantillonne les premières lignes
> et les teste contre des regex heuristics pour Apache, NGINX et Syslog.
> Si aucun format n'est reconnu, elle retourne `"unknown"`. Dans ce cas,
> `parser.py` tente successivement tous les parseurs dans l'ordre jusqu'à
> trouver celui qui parse la ligne correctement. Les lignes non parsables
> sont ignorées, et le programme continue avec les entrées valides,
> en signalant le nombre de lignes traitées par rapport au total.

---

**Q6 : Comment garantir l'absence de faux positifs dans la détection ?**

> Deux mécanismes limitent les faux positifs :
> - Les patterns de signatures dans `detector.py` sont volontairement précis :
>   on recherche des chaînes caractéristiques d'une attaque réelle
>   (ex. `UNION SELECT`, `<script`, `../../../`) et non des mots génériques.
> - La détection comportementale (brute-force, scan) exige un cumul de conditions :
>   pour le scan, il faut à la fois dépasser le seuil d'URIs distinctes
>   **et** avoir un taux de 404 supérieur à 50 %, ce qui évite de signaler
>   des crawlers légitimes très actifs.

---

## Chrono récapitulatif

| Temps cumulé | Durée | Action |
|:------------:|:-----:|--------|
| 0 min        | 1 min | **Étape 1** — Présentation du projet : arborescence, architecture modulaire, principe SRP |
| 1 min        | 3 min | **Étape 2** — Commande de base : analyse complète de `sample_access.log`, commentaire live de chaque section |
| 4 min        | 1 min 30 | **Étape 3** — Option OSINT : `--check-ip`, enrichissement géographique des IPs suspectes |
| 5 min 30     | 1 min 30 | **Étape 4** — Options avancées : `--bf-threshold`, `--scan-threshold`, `--no-report`, `--output-dir` |
| 7 min        | 1 min | **Étape 5** — Tests unitaires : `unittest discover`, résultat 25/25 OK |
| 8 min        | 2 min | **Questions jury** — Réponses préparées (voir section ci-dessus) |
| **10 min**   | —     | Fin de la démonstration |
