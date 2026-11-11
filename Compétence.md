# Compétences développées - MyPGP

Bilan établi le 11 novembre 2026 à partir des sources, configurations, tests et documents présents dans ce dépôt.

## Présentation

Implémentation pédagogique en Python de XOR, AES, RSA et compositions hybrides PGP-XOR/PGP-AES. L’interface en ligne de commande traite les entrées binaires et les représentations hexadécimales.

## Durée du projet

- Début du calendrier pédagogique : **21/09/2026**.
- Échéance indiquée : **18/10/2026**.
- Fenêtre prévue, dates incluses : **28 jours calendaires, soit 4 semaines** (27 jours d’écart entre les deux dates).
- Source : capture du tableau « Projets terminés » fournie par Nathan ; lecture de la date au pictogramme vert comme début et du drapeau rouge comme échéance. La date orange n’est pas utilisée comme début de développement.
- Historique du dépôt source local consulté : premier commit listé le **2026-09-23**, dernier commit listé le **2026-10-13**. Ces dates peuvent inclure des travaux après l’échéance et ne mesurent pas le temps de travail effectif.
- Heures investies, répartition individuelle et date exacte de fin de travail : **non renseignées**. Le commit d’import du portfolio ne représente pas la durée du projet.

## Lecture des niveaux de maîtrise

Ce bilan inventorie les compétences mobilisées et étayées par les livrables. Une analyse de dépôt ne permet pas de certifier l’acquisition individuelle, l’autonomie ni l’auteur de chaque réalisation. Les niveaux ci-dessous qualifient la profondeur d’utilisation visible **dans ce projet**, pas une certification ou un pourcentage de maîtrise personnelle de Nathan. Leur attribution individuelle reste à confirmer par ses contributions et une démonstration orale/pratique.

| Niveau | Signification dans ce document |
| --- | --- |
| Ciblé | Utilisation circonscrite à une fonction ou un outil ; expérience générale non établie. |
| Opérationnel | Utilisation concrète dans plusieurs tâches ou dans une fonctionnalité intégrée. |
| Approfondi | Plusieurs mécanismes internes sont implémentés ou articulés, avec des éléments de test ou d’analyse ; cela ne signifie pas expert du domaine. |

## Technologies et profondeur d’utilisation

| Technologie ou domaine | Niveau observé | Utilisation démontrée | Preuve dans le dépôt |
| --- | --- | --- | --- |
| Python 3, bibliothèque standard | Approfondi | Modules, classes, exceptions, bytes, bytearray et entiers arbitraires | [src](src) |
| XOR | Approfondi | Primitive réversible, découpage et limites de réutilisation des clés | [src/xor.py](src/xor.py) |
| AES-128/192/256 | Approfondi | Implémentation des tours, expansion de clé et transformations inverses | [src/aes.py](src/aes.py) |
| RSA, arithmétique modulaire | Approfondi | Génération depuis p/q, Carmichael, inverse et exponentiation modulaire | [src/rsa.py](src/rsa.py) |
| Composition hybride RSA + XOR/AES | Approfondi | Transport de clé et traitement symétrique du message | [src/hybrid.py](src/hybrid.py) |
| Encodage hexadécimal et little-endian | Opérationnel | Conversions exactes entre octets et entiers | [src/my_pgp.py](src/my_pgp.py) |
| unittest, sous-processus | Opérationnel | Vecteurs connus, tests CLI, erreurs et cas limites | [tests](tests) |
| Makefile, shell, stdin/stdout/stderr | Opérationnel | Lanceur, commandes de vérification et conventions de sortie | [Makefile](Makefile) |
| Mesure de performances Python | Ciblé | Benchmark RSA en fonction de la taille du module | [bonus/benchmark_rsa.py](bonus/benchmark_rsa.py) |
| Markdown, Git | Opérationnel | Cours, guide de compétences et versionnement | [COMPETENCES.md](COMPETENCES.md) |

## Inventaire détaillé des compétences

### Mathématiques et algorithmes

- Manipuler XOR bit à bit et expliquer sa réversibilité.
- Raisonner sur les octets, les blocs, les tailles de clés et les représentations.
- Implémenter les opérations de GF(2^8) utilisées par AES.
- Construire les tours SubBytes, ShiftRows, MixColumns et AddRoundKey ainsi que leurs inverses.
- Étendre une clé AES et prendre en compte les particularités d’AES-256.
- Calculer n, la fonction de Carmichael, un PGCD et un inverse modulaire.
- Choisir un exposant public compatible et exploiter les entiers de précision arbitraire.
- Utiliser pow à trois arguments pour éviter de construire des puissances intermédiaires énormes.
- Vérifier les contraintes sur les clés, les tailles et les entiers inférieurs au module.

### Architecture logicielle

- Séparer primitives cryptographiques et interface utilisateur.
- Définir des interfaces communes encrypt/decrypt.
- Factoriser les compositions dans HybridCipher et injecter la primitive symétrique.
- Distribuer les commandes par un registre de systèmes.
- Séparer calculs en octets, calculs en entiers et encodage textuel.
- Définir un format hybride à deux sorties : clé chiffrée et message chiffré.

### Données binaires et robustesse

- Traiter des données non UTF-8 sans conversion destructive en texte.
- Gérer LF, octets NUL, données vides et blocs incomplets.
- Distinguer mode bloc et traitement de messages de longueur quelconque.
- Gérer le remplissage nul sans retirer des octets légitimes au déchiffrement.
- Prendre en compte la perte de zéros terminaux dans la représentation minimale RSA.
- Restaurer une longueur de clé connue et refuser les cas ambigus.
- Valider l’hexadécimal, les séparateurs, les arguments et les erreurs de clé.
- Respecter les codes de sortie 0/84 et la séparation stdout/stderr.

### Analyse de sécurité

- Distinguer confidentialité, intégrité et authenticité.
- Expliquer pourquoi XOR répété ne possède pas les propriétés d’un masque jetable.
- Démontrer la fuite de répétitions d’un traitement AES de type ECB.
- Expliquer déterminisme et malléabilité du RSA sans padding.
- Identifier l’absence d’authentification des messages et des clés publiques.
- Reconnaître les limites de la composition de primitives faibles ou mal paramétrées.
- Distinguer le format pédagogique du standard OpenPGP.
- Présenter OAEP et GCM comme évolutions théoriques, sans les revendiquer comme implémentées.
- Identifier les limites de temps constant et de protection des clés dans une application Python.

### Tests, mesure et transmission

- Comparer les sorties à des vecteurs connus, et pas seulement tester un aller-retour.
- Vérifier séparément le cœur AES et les conversions imposées par le sujet.
- Tester les variantes AES, les messages binaires et les tailles limites.
- Vérifier les relations mathématiques RSA et les modules de 2 048 bits.
- Tester les compositions hybrides et les entrées invalides.
- Mesurer génération depuis p/q, chiffrement et déchiffrement séparément.
- Distinguer un benchmark local d’une garantie de performances.
- Automatiser lancement et tests ; rédiger un cours et des démonstrations de sécurité.

## Limites et compétences non attestées

- Il s’agit de cryptographie pédagogique : aucun chiffrement authentifié, RSA-OAEP, signature, génération de nombres premiers ou optimisation CRT n’est implémenté.
- Le programme ne constitue pas une implémentation interopérable d’OpenPGP.
- La CLI charge les entrées en mémoire ; le mot flux ne signifie pas traitement incrémental.
- La maîtrise de bibliothèques cryptographiques de production ou d’un audit professionnel n’est pas démontrée.

## Compétences transversales

- Traduire un sujet en fonctionnalités et organiser un livrable exécutable.
- Décomposer un problème, isoler les responsabilités et rechercher les causes d’erreurs.
- Lire et produire une documentation technique, des exemples et des commandes reproductibles.
- Utiliser Git pour versionner et livrer le travail.
- Relier un choix technique à ses contraintes et expliquer ses limites.

La gestion personnelle du temps, la répartition des tâches, le leadership et l’autonomie ne peuvent pas être déduits des seuls fichiers ; ils demandent un retour d’expérience individuel.

## Vérification et preuves

Les niveaux reposent sur une inspection des sources et sur les tests/rapports déjà présents. Aucun résultat d’exécution nouveau, taux de couverture ou succès de CI n’est revendiqué dans ce document. Les liens ci-dessus permettent de retrouver les implémentations. Les rapports historiques doivent être lus avec leur date, leurs conditions et leurs limites.

Le guide [COMPETENCES.md](COMPETENCES.md) et le cours [App.md](App.md) préexistants sont conservés ; ils détaillent les démonstrations et les limites cryptographiques.

## Points à préciser pour une présentation individuelle

- Modules conçus, codés, testés ou documentés personnellement par Nathan.
- Contributions réalisées en autonomie, en binôme ou avec accompagnement.
- Difficulté rencontrée, diagnostic et solution qu’il peut expliquer sans support.
- Capacité actuelle à reproduire ou adapter les réalisations dans un autre projet.
- Temps réellement consacré et résultats officiellement évalués, si disponibles.
