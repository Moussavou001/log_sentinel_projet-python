**Ouvert le** : vendredi 27 février 2026, 00:00

**À remettre** : mercredi 1 avril 2026, 23:59

Bonjour,

Comme présenté durant le cours, voici l\'exercice concernant le projet
de fin de module.

Concevoir et développer un outil original en Python répondant à une
problématique concrète en cybersécurité. Vous ne devez pas simplement
utiliser des outils existants, mais coder votre propre logique
d\'automatisation.

**Thématiques possibles (au choix)**

Vous avez carte blanche sur le sujet, tant qu\'il reste dans le domaine
de la sécurité :

-   **OSINT** : Crawler automatique (ex: recherche d\'emails, de
    sous-domaines ou d\'infos sur les réseaux sociaux).

-   **Pentest / Scan** : Scanner de vulnérabilités spécifique (ex:
    vérification de headers de sécurité, recherche de fichiers sensibles
    .env, .git).

-   **Analyse de Logs / Blue Team** : Analyseur intelligent de logs
    (Apache, Syslog) avec détection d\'attaques (Brute-force, SQLi) et
    génération de rapport.

-   **Post-Exploitation** : Script d\'énumération système (Windows ou
    Linux) pour identifier des vecteurs d\'élévation de privilèges.

-   **Interface Web** : Un tableau de bord (via Flask ou Streamlit) pour
    piloter vos scripts de scan.

**Contraintes Techniques (Barème de notation)**

Pour valider le module, votre script devra impérativement intégrer :

1.  **Manipulation de données complexes** : Utilisation justifiée de
    listes, dictionnaires et sets.

2.  **Modularité** : Le code doit être découpé en fonctions (une
    fonction = une action précise).

3.  **Robustesse** : Gestion des erreurs (le script ne doit pas
    \"crash\" si l\'utilisateur fait une mauvaise saisie).

4.  **Interaction** : Un menu clair ou des arguments en ligne de
    commande.

5.  **Utilisation d\'une bibliothèque tierce** : (ex: requests, scapy,
    beautifulsoup, rich, etc.).

**Livrables attendus**

1.  **Le Code Source** : Un fichier .py propre, commenté et organisé (ou
    un dépôt GitHub/GitLab).

2.  **Le fichier requirements.txt** : La liste des bibliothèques à
    installer pour faire tourner l\'outil.

3.  **La Documentation (README.md)** : \* À quoi sert l\'outil ?

Comment l\'installer et l\'utiliser ?

Un exemple de résultat (screenshot).

4.  **Démonstration (Soutenance)** : Une présentation rapide de 10
    minutes avec une démo \"live\" de l\'outil en action.

**Critères d\'évaluation**

-   **Fonctionnalité (40%)** : L\'outil remplit-il sa mission ? Est-il
    utile ?

-   **Qualité du code (30%)** : Propreté, nommage des variables, absence
    de répétitions inutiles.

-   **Originalité / Difficulté (20%)** : L\'effort de recherche et
    l\'originalité du concept.

-   **Documentation & Présentation (10%)** : Clarté des explications.
