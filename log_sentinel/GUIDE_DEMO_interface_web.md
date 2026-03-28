# Guide de Démonstration Interface Web — Log Sentinel

**Auteur :** NAOMIE NGWIDJOMBY MOUSSAVOU
**Module :** Python — Master 1 Cybersécurité
**Date de remise :** 1 avril 2026
**Durée de la démo :** 10 minutes

---

## Checklist avant la démo

Vérifier les points suivants **avant** d'entrer dans la salle de soutenance :

- [ ] Environnement virtuel activé : `D:\Python\env\Scripts\activate`
- [ ] Terminal ouvert dans le dossier projet : `D:\Python\log_sentinel_projet-python\log_sentinel`
- [ ] Dépendances installées : `pip install -r requirements.txt`
- [ ] Fichier démo présent : `samples/sample_access.log` (60 lignes, format NGINX)
- [ ] Connexion Internet disponible (si démonstration OSINT prévue)
- [ ] Navigateur ouvert sur `http://localhost:8501` (ou prêt à s'ouvrir)
- [ ] Streamlit déjà lancé OU prêt à être lancé devant le jury

---

## Etape 1 — Lancement de l'interface (30 secondes)

### Actions à effectuer

1. Ouvrir un terminal et activer l'environnement virtuel :
   ```
   D:\Python\env\Scripts\activate
   ```
2. Se placer dans le dossier du projet :
   ```
   cd D:\Python\log_sentinel_projet-python\log_sentinel
   ```
3. Lancer l'application :
   ```
   streamlit run app.py
   ```
4. Streamlit affiche dans le terminal :
   ```
   Local URL: http://localhost:8501
   ```
5. Le navigateur s'ouvre automatiquement (ou l'ouvrir manuellement sur `http://localhost:8501`).

### Ce que le jury observe

- Démarrage instantané en quelques secondes.
- Page web avec un thème sombre professionnel.
- Titre : **"Log Sentinel — Blue Team Analyzer"** avec icone bouclier.

### Phrase d'accroche suggérée

> "Log Sentinel est un analyseur de logs serveur orienté Blue Team. L'interface web Streamlit permet d'effectuer une analyse complète sans aucune commande, directement depuis un navigateur."

---

## Etape 2 — Présentation de l'interface (1 minute)

### Barre latérale (sidebar)

Montrer et commenter chaque élément :

- **Titre :** "Log Sentinel — Blue Team Security Analyzer v1.0.0"
- **Seuil brute-force** (`bf_threshold`) : champ numérique, valeur par défaut **5**.
  - Explication : nombre d'erreurs 401/403 d'une même IP avant levée d'alerte.
- **Seuil de scan** (`scan_threshold`) : champ numérique, valeur par défaut **10**.
  - Explication : nombre d'URIs distinctes sondées par une même IP avant alerte scan.
- **Checkbox "Enrichissement OSINT"** : désactivée par défaut, nécessite Internet.
- **Formats supportés** : Apache Combined Log, Nginx access log, Syslog RFC 3164.
- **Auteur et module** en bas de la sidebar.

### Zone principale

- **Zone d'upload** : glisser-déposer ou sélection d'un fichier `.log`, `.txt`, `.access`.
- **Bouton "Utiliser le fichier démo"** : charge automatiquement `samples/sample_access.log`.
- Message d'invite si aucun fichier n'est chargé : *"Chargez un fichier de log ou cliquez sur Utiliser le fichier démo pour démarrer l'analyse."*

### Point clé à mentionner

> "Les paramètres de la sidebar sont réactifs : si on modifie un seuil après une analyse, l'interface réinitialise automatiquement les résultats via le mécanisme `session_state` de Streamlit. Cela évite d'afficher des résultats incohérents."

---

## Etape 3 — Analyse du fichier démo (2 minutes)

### Actions à effectuer

1. Cliquer sur le bouton **"Utiliser le fichier démo"**.
2. Observer le spinner "Analyse du fichier démo en cours..." (quelques secondes).
3. Les résultats apparaissent automatiquement.

### Ce que le jury observe : les 5 métriques

| Metrique | Valeur attendue |
|---|---|
| Lignes lues | 60 |
| Entrees parsées | 60 |
| Alertes | 25 |
| IPs uniques | Variable |
| Taux d'erreur | Pourcentage |

### Score de risque

- Affiché en gras, coloré en **rouge** : **100/100 — CRITIQUE**
- Explication de la formule :
  - `min(50, nb_alertes × 2)` = 50 points (25 alertes × 2)
  - `min(30, taux_erreur × 0.6)` = points selon le taux d'erreur HTTP 4xx/5xx
  - `+20` si types sévères détectés : brute_force, scan, sql_injection, command_injection
  - Total plafonné à 100

### Phrase d'accroche suggérée

> "Ce fichier démo a été conçu pour déclencher le maximum d'alertes : injections SQL, XSS, parcours de répertoire, brute-force, scan de ports. Le score de 100/100 CRITIQUE confirme que tous les détecteurs fonctionnent."

---

## Etape 4 — Onglet Alertes (2 minutes)

### Actions à effectuer

1. Cliquer sur l'onglet **"Alertes (25)"**.
2. Observer le tableau coloré avec les 25 alertes.
3. Montrer le **filtre multiselect** en haut du tableau.
4. Décocher un ou deux types (ex. : désélectionner `brute_force`) pour montrer le filtrage dynamique.
5. Rétablir tous les types sélectionnés.

### Ce que le jury observe

- **Tableau HTML** avec colonnes : #, Type, IP, URI, Détails.
- **Badges colorés** par type d'attaque :
  - Rouge : `SQL INJECTION`, `COMMAND INJECTION`
  - Violet : `XSS`
  - Jaune : `PATH TRAVERSAL`, `SENSITIVE FILES`
  - Cyan : `MALICIOUS UA`
  - Orange : `BRUTE FORCE`
  - Bleu : `SCAN`
- Les URIs longues sont tronquées à 60 caractères avec "..." pour la lisibilité.
- Compteur : "X alerte(s) affichée(s) sur 25 détectée(s)."

### Point technique à mentionner

> "Le filtrage est entièrement côté client grâce au widget `multiselect` de Streamlit. La liste des types d'attaque est construite dynamiquement à partir des alertes réelles, sans codage en dur."

---

## Etape 5 — Onglet Statistiques (2 minutes)

### Actions à effectuer

1. Cliquer sur l'onglet **"Statistiques"**.
2. Commenter les 4 sections en ordre :
   - **Top IPs** (colonne gauche, haut)
   - **Codes HTTP** (colonne droite, haut)
   - **Top URIs ciblées** (colonne gauche, bas)
   - **Methodes HTTP** (colonne droite, bas)
3. Interagir avec un graphique : survoler une barre pour afficher la valeur.

### Ce que le jury observe

- **Dataframes interactifs** Streamlit (tri par colonne possible au clic).
- **Graphiques `bar_chart`** natifs Streamlit (interactifs, légende, survol).
- Top IPs : IP source + nombre de requêtes.
- Codes HTTP : répartition 200, 401, 403, 404, 500...
- Top URIs : chemins les plus sondés (tronqués à 60 caractères).
- Methodes HTTP : GET, POST, PUT, DELETE, HEAD...

### Point technique à mentionner

> "Les statistiques sont calculées par le module `LogStatistics` qui utilise les `Counter` et `defaultdict` de Python. L'interface se contente de les afficher : la séparation entre logique métier et présentation est strictement respectée."

---

## Etape 6 — Onglet OSINT (1 minute)

### Actions à effectuer

**Si connexion Internet disponible :**

1. Retourner dans la **sidebar**, cocher **"Enrichissement OSINT"**.
2. Cliquer à nouveau sur **"Utiliser le fichier démo"** (relance l'analyse avec OSINT).
3. Cliquer sur l'onglet **"OSINT"**.
4. Observer le tableau de géolocalisation.

**Si pas de connexion Internet :**

1. Montrer l'onglet OSINT désactivé avec le message d'information.
2. Expliquer le fonctionnement.

### Ce que le jury observe

- **Tableau de géolocalisation** : colonnes IP, Pays, Ville, FAI, Proxy.
- Colonne "Proxy" : affiche "OUI" avec icone d'alerte si IP proxy détectée.
- Limité aux **5 premières IPs suspectes** pour respecter les limites de l'API gratuite.

### Point technique à mentionner

> "L'enrichissement OSINT interroge l'API gratuite `ip-api.com/batch` sans clé d'authentification. Le module `OSINTChecker` est optionnel et isolé : si le réseau est indisponible, l'analyse principale n'est pas affectée."

---

## Etape 7 — Onglet Rapport HTML (1 minute)

### Actions à effectuer

1. Cliquer sur l'onglet **"Rapport HTML"**.
2. Lire le message d'introduction affiché.
3. Cliquer sur le bouton **"Generer le rapport HTML"** (bouton primaire bleu).
4. Observer le spinner "Génération du rapport..."
5. Une fois généré :
   - Lire le message de succès avec le chemin : `reports/report.html`
   - Montrer le **bouton de téléchargement** "Télécharger le rapport HTML"
   - Faire défiler l'**aperçu inline** du rapport dans l'iframe.

### Ce que le jury observe

- Rapport généré localement dans `log_sentinel/reports/report.html`.
- Bouton `download_button` Streamlit : télécharge `log_sentinel_report.html`.
- Aperçu intégré via `st.components.v1.html` dans une iframe scrollable (hauteur 600px).
- Le rapport est **autonome** : CSS intégré, aucune dépendance externe, ouvrable hors ligne.

### Point technique à mentionner

> "Le rapport HTML est produit par le module `HTMLReporter`. Il est entièrement auto-contenu : un seul fichier `.html` que l'on peut envoyer par e-mail ou archiver sans dépendance externe. L'aperçu inline dans Streamlit permet de vérifier le contenu avant téléchargement."

---

## Questions jury — Réponses préparées

### Q1 — Pourquoi avoir choisi Streamlit plutôt que Flask ou Django ?

> Streamlit est conçu pour des applications data/analyse en Python pur. Il n'y a pas de HTML/CSS/JavaScript à écrire : chaque widget (tableau, graphique, bouton) correspond à un appel de fonction Python. Pour un projet d'analyse de logs orienté cybersécurité, c'est le bon outil : rapide à développer, lisible, et le résultat est professionnel sans sur-ingénierie.

### Q2 — Comment fonctionne le `session_state` et pourquoi est-il nécessaire ?

> Streamlit re-exécute tout le script Python à chaque interaction utilisateur (c'est son modèle de rendu). Sans `session_state`, les résultats d'analyse seraient perdus à chaque clic. Le `session_state` est un dictionnaire persistant entre les rerenders. Ici, les résultats du pipeline sont stockés dans `st.session_state["resultats"]`. De plus, une clé `derniere_cle_params` détecte si les seuils ont changé, et réinitialise les résultats pour forcer une nouvelle analyse cohérente.

### Q3 — Comment sont générés les badges colorés dans le tableau des alertes ?

> Les badges sont des balises HTML `<span>` avec des classes CSS définies dans un bloc `st.markdown(..., unsafe_allow_html=True)` injecté en début d'application. Chaque type d'attaque a sa propre classe CSS (ex. `.badge-sql_injection`, `.badge-xss`). La fonction `_badge_html(attack_type)` construit dynamiquement le HTML de chaque badge. Streamlit autorise l'injection HTML brut via le paramètre `unsafe_allow_html`.

### Q4 — Quelle est la différence entre l'upload de fichier et le bouton "fichier démo" ?

> Les deux alimentent le même pipeline `_executer_pipeline()`. La différence est la source du contenu :
> - Le **bouton démo** lit directement `samples/sample_access.log` depuis le disque via `Path.read_text()`.
> - L'**upload** lit le contenu depuis l'objet `UploadedFile` de Streamlit (données en mémoire), qui est décodé en UTF-8.
> Dans les deux cas, le contenu est écrit dans un fichier temporaire (`tempfile.NamedTemporaryFile`) pour que `LogLoader` puisse le lire de façon uniforme, puis ce fichier est supprimé après l'analyse.

### Q5 — Comment l'interface détecte-t-elle le format du fichier de log ?

> La détection est réalisée par `LogLoader.detect_format()`. Elle échantillonne les premières lignes du fichier et les teste contre des expressions régulières propres à chaque format (Apache Combined Log, Nginx, Syslog RFC 3164). Le format qui correspond au plus grand nombre de lignes est retenu. Si aucun format ne correspond, la méthode retourne `"unknown"` et `LogParser` tente alors tous les parseurs en séquence. Le format détecté est affiché à l'utilisateur sous le résumé des métriques.

### Q6 — Pourquoi l'OSINT est-il limité à 5 IPs ?

> L'API `ip-api.com` est gratuite et sans clé d'authentification, mais elle impose une limite de débit (45 requêtes par minute). Pour ne pas dépasser ce quota et garder l'analyse rapide, le code limite la requête batch aux 5 premières IPs suspectes distinctes. Ce choix est configurable dans `OSINTChecker.check_ips(max_ips=5)`. Dans un contexte production, on utiliserait une API payante ou un service comme AbuseIPDB avec authentification.

### Q7 — Comment garantissez-vous que l'interface est cohérente avec la CLI (`main.py`) ?

> Le pipeline d'analyse est identique dans les deux interfaces : elles partagent les mêmes modules `src/`. La seule duplication acceptée est la fonction `_calculer_score_risque` (copiée dans `app.py` et `main.py`), ce qui était un choix délibéré pour éviter une dépendance circulaire. Les 25 tests unitaires (`tests/`) valident les modules `src/` indépendamment des deux interfaces, ce qui garantit la cohérence des résultats.

---

## Chrono récapitulatif

| Etape | Action | Duree |
|---|---|---|
| Avant la démo | Checklist, lancement Streamlit | Hors chrono |
| Etape 1 | Lancement + ouverture navigateur | 30 secondes |
| Etape 2 | Présentation sidebar et zone upload | 1 minute |
| Etape 3 | Clic démo, métriques, score 100/100 CRITIQUE | 2 minutes |
| Etape 4 | Onglet Alertes, filtres multiselect, badges | 2 minutes |
| Etape 5 | Onglet Statistiques, graphiques, dataframes | 2 minutes |
| Etape 6 | Onglet OSINT (activer sidebar si possible) | 1 minute |
| Etape 7 | Onglet Rapport : génération + téléchargement + aperçu | 1 minute |
| **Total** | | **~10 minutes** |

---

*Guide rédigé pour la soutenance du projet Log Sentinel — Master 1 Cybersécurité — 1 avril 2026.*
