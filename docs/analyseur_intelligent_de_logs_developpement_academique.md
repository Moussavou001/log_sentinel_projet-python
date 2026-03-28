

---

# Développement du thème

# **Analyseur Intelligent de Logs (Blue Team)**

## 1. Introduction générale

Dans un contexte où les systèmes d’information sont continuellement exposés à des tentatives d’intrusion, les **journaux d’événements (logs)** constituent une source essentielle pour la détection d’activités malveillantes. Les serveurs web, les systèmes Linux, les pare-feu et les applications enregistrent dans leurs logs des informations précieuses sur les accès, les erreurs, les requêtes et les comportements anormaux.

L’objectif du projet **Log Sentinel** est de concevoir un outil Python capable d’**analyser automatiquement des fichiers de logs**, de **repérer des comportements suspects** et de **présenter les résultats sous forme exploitable**, aussi bien dans le terminal que dans un **rapport HTML**.

Ce projet s’inscrit dans une logique **Blue Team**, c’est-à-dire orientée défense, surveillance et détection. Contrairement à un outil offensif, il vise à aider un administrateur système, un analyste SOC ou un étudiant en cybersécurité à :

- identifier des tentatives de **brute-force**
- repérer des indicateurs de **SQL injection**
- détecter des traces de **XSS**
- relever des accès à des **fichiers sensibles**
- identifier des comportements de **scan**
- produire un **rapport synthétique et professionnel**

---

## 2. Problématique

Les logs sont souvent volumineux, hétérogènes et difficiles à exploiter manuellement.\
Un administrateur ne peut pas parcourir efficacement des milliers de lignes pour identifier rapidement :

- quelles IPs sont les plus actives
- quelles requêtes sont anormales
- quels chemins sensibles ont été ciblés
- si une attaque de type brute-force est en cours
- si un outil de scan automatisé est utilisé contre le serveur

La problématique est donc la suivante :

> **Comment automatiser l’analyse de logs de sécurité afin de détecter rapidement des comportements suspects, tout en restant dans une implémentation Python modulaire, robuste et exploitable en entreprise ?**

---

## 3. Objectif principal du projet

L’objectif principal est de développer un **analyseur intelligent de logs** qui :

1. **charge** un fichier de log
2. **détecte automatiquement son format**
3. **parse chaque ligne**
4. **analyse les événements**
5. **détecte plusieurs types d’attaques**
6. **affiche les résultats**
7. **génère un rapport HTML lisible**

---

## 4. Intérêt cybersécurité du projet

Ce projet présente un intérêt fort sur le plan cybersécurité pour plusieurs raisons :

### 4.1 Détection précoce

L’outil permet d’identifier des signaux faibles ou des attaques en cours avant qu’elles ne causent un impact plus important.

### 4.2 Automatisation

Il réduit le temps nécessaire à l’analyse manuelle de fichiers de logs.

### 4.3 Valeur SOC / Blue Team

Il reproduit à petite échelle une logique proche des outils de :

- SIEM
- détection d’incidents
- corrélation de logs
- triage d’alertes

### 4.4 Projet réaliste

Les logs Apache, Nginx et Syslog sont couramment utilisés en environnement réel.

---

# 5. Fondements théoriques du projet

## 5.1 Qu’est-ce qu’un log ?

Un **log** est un enregistrement chronologique d’événements généré par un système, un serveur ou une application.

Exemples d’informations présentes :

- adresse IP source
- date et heure
- méthode HTTP
- ressource demandée
- code de retour HTTP
- user-agent
- message système

### Source :

- Apache HTTP Server Documentation — Log Files\
  [https://httpd.apache.org/docs/current/logs.html](https://httpd.apache.org/docs/current/logs.html)

- Nginx Logging Documentation\
  [https://nginx.org/en/docs/http/ngx\_http\_log\_module.html](https://nginx.org/en/docs/http/ngx_http_log_module.html)

- RFC 3164 — The BSD Syslog Protocol\
  [https://datatracker.ietf.org/doc/html/rfc3164](https://datatracker.ietf.org/doc/html/rfc3164)

---

## 5.2 Importance des logs en cybersécurité

Les logs sont un pilier de :

- la **détection d’incidents**
- la **réponse à incident**
- la **traçabilité**
- la **forensique**
- la **conformité**

Ils permettent de répondre à des questions essentielles :

- Qui a accédé à quoi ?
- Quand ?
- Depuis quelle IP ?
- Avec quel comportement ?
- Quelle erreur a été générée ?

### Source :

- NIST SP 800-92 — Guide to Computer Security Log Management\
  [https://csrc.nist.gov/pubs/sp/800/92/final](https://csrc.nist.gov/pubs/sp/800/92/final)

---

# 6. Types d’attaques détectées dans le projet

## 6.1 Brute-Force

### Définition

Une attaque par brute-force consiste à tenter de nombreuses authentifications successives afin de deviner un mot de passe ou un identifiant valide.

### Détection

Analyse des requêtes répétées, erreurs HTTP et fréquence par IP.

---

## 6.2 SQL Injection (SQLi)

### Détection

Recherche de patterns suspects comme `UNION SELECT`, `OR 1=1`, etc.

---

## 6.3 Cross-Site Scripting (XSS)

### Détection

Recherche de balises `<script>`, `javascript:`, `onerror=`, etc.

---

## 6.4 Path Traversal

### Détection

Recherche de `../`, `%2e%2e%2f`, `/etc/passwd`.

---

## 6.5 Fichiers sensibles

### Détection

Recherche de `.env`, `.git`, `wp-config.php`, etc.

---

## 6.6 Command Injection

### Détection

Recherche de `;`, `|`, `$()`, etc.

---

## 6.7 User-Agent malveillant

### Détection

Analyse des outils comme `sqlmap`, `nmap`, `nikto`.

---

## 6.8 Scan de ressources

### Détection

Nombre élevé d’URI distinctes par IP.

---

# 7. Choix techniques

- Python
- re
- argparse
- collections
- requests
- rich

---

# 8. Architecture

- Chargement
- Parsing
- Détection
- Statistiques
- OSINT
- Reporting
- CLI

---

# 9. Méthodologie

- Détection par signature
- Détection par seuil

---

# 10. Limites

- Pas de corrélation temporelle
- Regex limitées
- Formats limités
- Score heuristique

---

# 11. Améliorations

- Fenêtre temporelle
- Interface web
- Export JSON/CSV
- ML

---

# 12. Conclusion

Le projet **Log Sentinel** constitue une base solide pour un outil de cybersécurité défensive orienté Blue Team, avec une forte valeur pédagogique et technique.

