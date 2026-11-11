# Préparer les quatre compétences

Ce dossier fournit une implémentation et des preuves techniques. Les XP et les
niveaux sont attribués par l'évaluation : exécuter les tests ne garantit pas leur
validation. Il faut savoir expliquer les choix et les limites du projet.

## 1. Expliquer les algorithmes et évaluer leur sécurité

**Objectif :** expliquer le fonctionnement, les hypothèses et une faiblesse
concrète de chaque système. Le cours `App.md` présente les étapes ;
`python3 bonus/demo_security.py` démontre plusieurs limites avec des assertions.

| Système | Propriété recherchée | Limite démontrable ici |
| --- | --- | --- |
| XOR | Réversibilité : `(M XOR K) XOR K = M` | Réutiliser K révèle les relations entre les messages |
| AES | Permutation de blocs dépendant de la clé | En ECB, des blocs identiques produisent des chiffrés identiques |
| RSA | Déchiffrer avec un exposant privé | Sans padding, chiffrement déterministe et malléable |
| Hybride | Protéger une petite clé RSA et traiter le message en symétrique | La composition conserve les faiblesses des primitives et du format |

### XOR : conditions du masque jetable

Un masque jetable demande une clé uniforme, indépendante, secrète, aussi longue
que le message et utilisée une seule fois. Ici, la clé est répétée par bloc.
Pour deux blocs alignés, `C1 XOR C2 = M1 XOR M2`, après annulation de la
convention d'inversion des octets. Connaître un bloc clair révèle la clé.
Modifier un bit du chiffré modifie un bit du clair sans détection.

### AES : primitive et mode d'utilisation

AES travaille sur 128 bits avec une clé de 128, 192 ou 256 bits et respectivement
10, 12 ou 14 tours. SubBytes fournit la non-linéarité ; ShiftRows et MixColumns
propagent l'influence des octets ; AddRoundKey intègre la clé de tour.
Le dernier tour omet MixColumns. Voir [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final).

Le découpage du sujet chiffre les blocs indépendamment : même bloc et même clé,
même résultat. On peut observer les répétitions ou réordonner des blocs complets
sans que le programme signale une altération. ECB est décrit dans
[NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).
GCM ajoute une authentification avec un tag ; son utilisation exige notamment
la maîtrise des nonces, voir
[NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).
Augmenter la taille de clé AES ne corrige pas les défauts d'ECB.

### RSA : hypothèses et limites

`n = p*q`, `λ(n) = ppcm(p−1, q−1)`, `pgcd(e, λ(n)) = 1`,
`d = e⁻¹ mod λ(n)`. Le public est `(e,n)`, le privé `(d,n)`.
Le chiffrement calcule `m^e mod n`, le déchiffrement `c^d mod n`.
Factoriser n permet de retrouver λ et d ; de petits modules sont vulnérables.
Les premiers publics du sujet servent uniquement à tester.

Le RSA brut du projet est déterministe. Sa structure multiplicative permet de
modifier C en `C * r^e mod n` pour obtenir `M * r mod n` au déchiffrement.
Un encodage probabiliste comme RSA-OAEP fait partie d'un schéma complet de
chiffrement ; il n'est pas ajouté ici pour conserver les vecteurs du sujet.
La distinction primitive/schéma est exposée dans
[RFC 8017](https://www.rfc-editor.org/rfc/rfc8017).

### Sécurité de la composition

Le destinataire doit disposer d'une clé publique authentifiée : si un attaquant
substitue sa clé, il récupère la clé symétrique. Le format actuel ne fournit ni
signature ni tag et n'associe pas cryptographiquement les deux lignes.
Une absence d'erreur au déchiffrement ne prouve donc pas l'authenticité.
Le code Python n'offre pas de garantie de temps constant ; la confidentialité
des fichiers de clé et des arguments de commande est aussi extérieure au schéma.

À l'oral, distinguer confidentialité, intégrité et authenticité. Proposer une
évolution : clé de session générée avec un générateur cryptographique, transport
RSA-OAEP, AES-GCM, vérification du tag avant livraison du clair, format versionné
contenant nonce et métadonnées, et authentification de la clé du destinataire.
Il s'agit d'une évolution à construire, pas de fonctionnalités disponibles ici.

## 2. Concevoir une architecture cryptographique modulaire hybride

**Code :** `src/hybrid.py`, `src/pgp_xor.py`, `src/pgp_aes.py`, `src/my_pgp.py`.

```text
Chiffrement :
  clé de session + clé publique RSA → RSA → clé chiffrée (ligne 1)
  message + clé de session          → XOR/AES → message chiffré (ligne 2)

Déchiffrement :
  clé chiffrée + clé privée RSA     → RSA → clé de session
  message chiffré + clé de session  → XOR/AES → message clair
```

`HybridCipher` reçoit un module symétrique exposant les opérations
`encrypt(data, key, block_mode)` et `decrypt(...)`. Il partage le parsing de la
clé composite, le transport RSA et la restitution de la longueur de clé.
Les deux modules PGP configurent cette composition. Le registre `SYSTEMS`
permet à la CLI de sélectionner le système sans intégrer les calculs à la CLI.

Les primitives manipulent des octets ; RSA utilise des entiers en interne.
La CLI gère les conventions textuelles. RSA ne traite que la clé de session,
tandis que la primitive symétrique traite le message, même s'il dépasse n.
La clé symétrique doit néanmoins avoir une valeur entière strictement inférieure
au module RSA. Elle est fournie par l'utilisateur comme exigé pour le débogage.

Le déchiffrement utilise la première ligne comme préfixe de la clé privée,
et la seconde sur stdin. Il ne lit pas les deux lignes automatiquement.
Ce format pédagogique n'est pas un format OpenPGP standard.

**Preuves :** `tests/test_pgp_aes.py` vérifie les deux lignes exactes du sujet,
le mode bloc, le flux binaire et les clés terminées par des zéros.
`tests/test_pgp_xor.py` couvre l'autre composition et les entrées invalides.

**Question à préparer :** pourquoi chiffrer la clé avec RSA et le message avec
AES ? Réponse : une clé est petite et le chiffrement symétrique traite des
blocs sans la contrainte `message entier < n`, avec un coût adapté aux fichiers.
Cette implémentation pédagogique en Python ne cherche pas les performances
d'une bibliothèque AES optimisée.

## 3. Implémenter du chiffrement symétrique sur des données binaires

**Code :** `src/xor.py` et `src/aes.py`.

- XOR : découpage à la taille de la clé, inversion de bloc, XOR et inversion au déchiffrement.
- AES : état rempli colonne par colonne, calcul dans GF(2^8) modulo `0x11b`, expansion de clé, tours et transformations inverses.
- AES-256 : substitution supplémentaire au milieu de chaque groupe de huit mots lors de l'expansion.
- Flux : traitement des LF, NUL et octets non UTF-8 sans décodage du clair.
- Bloc CLI : une seule ligne ; retrait du LF terminal comme demandé par le sujet.

Le mot « flux » du sujet désigne ici le traitement d'un message de taille
quelconque par blocs. Ce n'est ni un mode CTR ni une lecture incrémentale :
la CLI charge actuellement toute l'entrée en mémoire.

**Preuves :** `tests/test_aes.py` compare le cœur aux vecteurs connus des trois
variantes, puis vérifie la conversion du sujet séparément. La CLI est testée
sur toutes les valeurs d'octet et les tailles 0, 1, 15, 16 et 17.
`tests/test_cli.py` contrôle XOR, les erreurs et les conversions.

Le remplissage nul ne permet pas de retrouver la longueur originale :
`b'A'` et `b'A\x00'` peuvent produire le même bloc rempli. Le déchiffrement
conserve les zéros ; utiliser `rstrip(b'\x00')` serait une perte de données.
Les allers-retours sont donc exacts jusqu'au remplissage requis par le sujet.
L'hexadécimal est un encodage ; inverser des octets n'ajoute aucune sécurité.

## 4. Implémenter RSA avec arithmétique multi-précision et mesurer ses performances

**Code :** `src/rsa.py` et `bonus/benchmark_rsa.py`.

Python fournit des entiers de précision arbitraire : le module ne se limite
pas à 32 ou 64 bits. `pow(m, e, n)` effectue l'exponentiation modulaire sans
construire la puissance entière `m**e`. L'inverse utilise `pow(e, -1, λ)`.
Le choix de e parcourt 65537, 257, 17, 5 et 3 dans l'ordre décroissant,
en vérifiant `e < λ` et `pgcd(e, λ) = 1`, conformément aux exemples du sujet.

**Preuves :** les vecteurs RSA de `tests/test_rsa.py` et les tests de module
2 048 bits dans `tests/test_rsa_large.py`. Ceux-ci vérifient `n = p*q`,
`e*d mod λ = 1`, les valeurs 0, 1, p et n−1, et les octets binaires de l'API.
La valeur p teste aussi le déchiffrement d'un entier non premier avec n.
La génération suppose p et q premiers comme autorisé par le sujet ; elle
ne teste pas la primalité et ne génère pas de nouveaux nombres premiers.

Mesure effectuée avec `make benchmark`, Python 3.12.3, médiane de cinq
opérations sur cette machine (temps en millisecondes) :

| Bits du module | Génération à partir de p et q | Chiffrement | Déchiffrement |
| --- | ---: | ---: | ---: |
| 512 | 0,014 | 0,028 | 1,027 |
| 2048 | 0,028 | 0,194 | 38,894 |

Ces mesures excluent la recherche de premiers, les E/S et le lancement de la
CLI. Elles varient avec le matériel et ne constituent pas un seuil garanti.
Le déchiffrement utilise un exposant beaucoup plus grand que 65537, d'où son
coût. Le format privé contient seulement d et n : l'optimisation CRT exigerait
de conserver p et q dans un format supplémentaire. Aucun CRT n'est implémenté.

## Démonstration pour l'évaluation

1. Exécuter `make tests_run` et expliquer la différence entre un vecteur connu et un aller-retour, qui pourrait masquer deux erreurs compensées.
2. Montrer l'exemple PGP-AES du README et les deux chemins dans `HybridCipher`.
3. Montrer le flux contenant les 256 valeurs d'octet et expliquer le remplissage.
4. Exécuter `make benchmark` et expliquer précision arbitraire, exponentiation modulaire et Carmichael.
5. Exécuter `python3 bonus/demo_security.py` et expliquer les faiblesses observées et les protections à ajouter.

Le sujet conseille aussi un deuxième cryptosystème asymétrique et propose des
extensions (signatures, génération de premiers, padding). Elles ne sont pas
implémentées dans cet état du projet. Les quatre compétences ci-dessus sont
étayées par RSA et les deux compositions hybrides ; la grille détaillée de
l'évaluateur reste nécessaire pour savoir quelles extensions sont attendues.
