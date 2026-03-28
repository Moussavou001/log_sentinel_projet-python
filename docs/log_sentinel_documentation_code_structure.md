# 🛡️ LOG SENTINEL — Développement Complet & Structuré

---

## 📁 Architecture Finale du Projet

```
log_sentinel/
├── log_analyzer.py        ← Script principal (unique fichier .py)
├── requirements.txt       ← Dépendances
├── README.md              ← Documentation complète
└── samples/
    └── sample_access.log  ← Fichier de test fourni
```

---

## 1. log_analyzer.py — Code Source Complet

### 🎯 Objectif
Analyse intelligente de logs de sécurité (Apache, Nginx, Syslog) avec détection d’attaques et génération de rapport HTML.

---

### 🔧 Sections principales du code

#### 1. Configuration
- Centralisation des paramètres dans un dictionnaire `CONFIG`
- Seuils modifiables (Brute-force, scan)

#### 2. Patterns d’attaque
- Regex optimisées (pré-compilées)
- Basées sur OWASP Top 10

#### 3. Parsing des logs
- Détection automatique du format
- Normalisation des données

#### 4. Détection des attaques
- SQL Injection
- XSS
- Path Traversal
- Command Injection
- Fichiers sensibles
- Scanners connus

#### 5. Analyse avancée
- Brute-force (401/403)
- Détection de scanners (URIs multiples)
- Statistiques globales

#### 6. OSINT
- Vérification IP via API externe

#### 7. Rapport HTML
- Dashboard complet
- Score de risque
- Visualisation des attaques

#### 8. Interface CLI
- Arguments personnalisables
- Utilisation simple et flexible

---

### 🧠 Concepts techniques clés

- `dict` → configuration et données structurées
- `list` → stockage des entrées
- `set` → unicité (IPs, URIs)
- `defaultdict` → simplification des accumulations
- `regex` → détection avancée
- `argparse` → CLI professionnelle

---

### 📌 Points forts

- Architecture modulaire
- Code robuste (gestion d’erreurs complète)
- Compatible multi-formats
- Rapport HTML autonome
- Interface terminal avancée (Rich)

---

## 2. requirements.txt

```
requests>=2.31.0
rich>=13.7.0
```

---

## 3. README.md — Documentation

### 🎯 Objectif
Fournir une documentation claire pour installation, utilisation et compréhension technique.

---

### 📌 Contenu principal

#### ✔ Présentation
Outil Blue Team pour analyser automatiquement des logs serveur.

#### ✔ Détections
- Brute-force
- SQL Injection
- XSS
- Path Traversal
- Command Injection
- Fichiers sensibles
- Scanners

#### ✔ Installation

```
pip install -r requirements.txt
```

#### ✔ Utilisation

```
python log_analyzer.py -f access.log
```

#### ✔ Options avancées
- `--bf-threshold`
- `--scan-threshold`
- `--report`
- `--no-report`
- `--check-ip`

---

### 🏗️ Architecture technique

- Parsing
- Détection
- Analyse
- Reporting

---

### ⚖️ Avertissement

Utilisation uniquement sur systèmes autorisés.

---

## ✅ Récapitulatif Qualité Projet

| Critère | Validation |
|--------|----------|
| Modularité | ✅ |
| Robustesse | ✅ |
| Performance | ✅ |
| Lisibilité | ✅ |
| Documentation | ✅ |
| Fonctionnalités | ✅ |

---

## 🚀 Conclusion

Log Sentinel est un outil complet de cybersécurité orienté Blue Team permettant :

- Analyse automatisée des logs
- Détection intelligente d’attaques
- Visualisation claire via HTML
- Aide à la prise de décision sécurité

---

💡 Projet idéal pour :
- PFE
- SOC / Blue Team
- Audit sécurité
- Démonstration technique avancée

