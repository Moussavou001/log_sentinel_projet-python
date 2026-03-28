# Analyseur Intelligent de Logs (Blue Team)

## 1. Introduction générale

Dans un contexte où les systèmes d’information sont continuellement exposés à des tentatives d’intrusion, les journaux d’événements (logs) constituent une source essentielle pour la détection d’activités malveillantes. Les serveurs web, les systèmes Linux, les pare-feu et les applications enregistrent dans leurs logs des informations précieuses sur les accès, les erreurs, les requêtes et les comportements anormaux.

L’objectif du projet Log Sentinel est de concevoir un outil Python capable d’analyser automatiquement des fichiers de logs, de repérer des comportements suspects et de présenter les résultats sous forme exploitable, aussi bien dans le terminal que dans un rapport HTML.

Ce projet s’inscrit dans une logique Blue Team, c’est-à-dire orientée défense, surveillance et détection.

---

## 2. Problématique

Les logs sont souvent volumineux, hétérogènes et difficiles à exploiter manuellement.

> Comment automatiser l’analyse de logs de sécurité afin de détecter rapidement des comportements suspects, tout en restant dans une implémentation Python modulaire, robuste et exploitable en entreprise ?

---

## 3. Objectif principal

- Charger un fichier de log
- Détecter automatiquement son format
- Parser chaque ligne
- Analyser les événements
- Détecter plusieurs types d’attaques
- Afficher les résultats
- Générer un rapport HTML lisible

---

## 4. Intérêt cybersécurité

- Détection précoce
- Automatisation
- Logique SOC / Blue Team
- Projet réaliste

---

## 5. Fondements théoriques

### 5.1 Définition d’un log

Un log est un enregistrement chronologique d’événements généré par un système.

### 5.2 Importance

- Détection d’incidents
- Forensique
- Traçabilité
- Conformité

---

## 6. Types d’attaques détectées

### 6.1 Brute-Force

Tentatives répétées d’authentification.

### 6.2 SQL Injection

Injection de code SQL dans les entrées utilisateur.

### 6.3 XSS

Injection de JavaScript dans une page web.

### 6.4 Path Traversal

Accès à des fichiers via manipulation de chemins.

### 6.5 Fichiers sensibles

Accès à .env, .git, etc.

### 6.6 Command Injection

Exécution de commandes système.

### 6.7 Scanners User-Agent

Détection d’outils comme sqlmap, nikto.

### 6.8 Scan de ressources

Exploration massive d’URI.

---

## 7. Choix techniques

- Python
- re
- argparse
- collections
- requests
- rich

---

## 8. Architecture

- Chargement
- Parsing
- Détection
- Statistiques
- OSINT
- Reporting
- CLI

---

## 9. Méthodologie

- Détection par signatures
- Détection par seuils

---

## 10. Limites

- Pas de corrélation temporelle avancée
- Détection basée sur regex
- Formats limités
- Score heuristique

---

## 11. Améliorations

- Fenêtre temporelle
- Plus de formats
- Export JSON/CSV
- Interface web
- Géolocalisation
- Machine learning

---

## 12. Conclusion

Log Sentinel est un outil cohérent et pertinent pour un projet de cybersécurité. Il permet de transformer des logs bruts en informations exploitables, avec une approche modulaire et pédagogique.

