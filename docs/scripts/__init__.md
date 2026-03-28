# __init__.py — Fichiers d'initialisation des packages

## Rôle général

En Python, tout dossier contenant un fichier `__init__.py` est reconnu comme un **package**
(un module importable). Sans ce fichier, Python ne peut pas importer les modules du dossier.

Log Sentinel en possède deux :

| Fichier | Package | Rôle |
|---|---|---|
| `src/__init__.py` | `src/` | Déclare les métadonnées du package et exporte `LogLoader` |
| `tests/__init__.py` | `tests/` | Marque le dossier comme package pour `unittest discover` |

---

## src/__init__.py

### Contenu

```python
"""
Log Sentinel - Analyseur de Logs Blue Team
===========================================
Boîte à outils Python pour charger, parser et analyser des fichiers de logs
issus des formats serveur courants (Apache, Nginx, Syslog, etc.).
"""

__version__ = "1.0.0"
__author__  = "NAOMIE NGWIDJOMBY MOUSSAVOU"
__module__  = "Python / Master 1 Cybersécurité"
__license__ = "MIT"

from .loader import LogLoader

__all__ = [
    "LogLoader",
]
```

### Variables spéciales (dunders)

| Variable | Valeur | Rôle |
|---|---|---|
| `__version__` | `"1.0.0"` | Version sémantique du package |
| `__author__` | `"NAOMIE NGWIDJOMBY MOUSSAVOU"` | Auteur du projet |
| `__module__` | `"Python / Master 1 Cybersécurité"` | Contexte académique |
| `__license__` | `"MIT"` | Licence d'utilisation |

Ces variables sont une convention Python standard — elles n'ont pas d'effet sur l'exécution
mais sont lisibles par les outils comme `pip`, `setuptools` ou simplement via
`import src; print(src.__version__)`.

### Import public et `__all__`

```python
from .loader import LogLoader

__all__ = ["LogLoader"]
```

- `from .loader import LogLoader` : importe `LogLoader` dans l'espace de noms de `src`,
  ce qui permet d'écrire `from src import LogLoader` depuis n'importe quel module du projet,
  au lieu de `from src.loader import LogLoader`.

- `__all__` : liste explicite de ce qui est exporté si quelqu'un écrit `from src import *`.
  C'est une bonne pratique qui documente l'**interface publique** du package.

### Pourquoi seul `LogLoader` est exporté ?

`LogLoader` est le point d'entrée naturel du pipeline : c'est toujours lui qu'on instancie
en premier pour charger un fichier. Les autres classes (`LogParser`, `AttackDetector`, etc.)
sont importées directement depuis leurs modules respectifs dans `main.py` et `app.py`.

---

## tests/__init__.py

### Contenu

```python
# Tests Log Sentinel
```

Fichier intentionnellement vide (hormis le commentaire). Sa seule fonction est de
**transformer le dossier `tests/` en package Python**, ce qui permet à la commande :

```bash
python -m unittest discover -s tests -v
```

de découvrir automatiquement tous les fichiers `test_*.py` dans le dossier.

Sans ce fichier, `unittest discover` ne pourrait pas importer les modules de test
sous forme de `tests.test_detector`, `tests.test_statistics`, etc.

---

## Points clés techniques

| Concept | Explication |
|---|---|
| Package Python | Dossier + `__init__.py` = module importable |
| Import relatif (`.loader`) | Le point `.` désigne le package courant (`src/`) |
| `__all__` | Contrôle ce qui est exposé avec `from package import *` |
| Dunders (`__version__`, etc.) | Convention de métadonnées lisible par les outils Python |
| `__init__.py` vide | Suffisant pour déclarer un package ; aucun code requis |
