# my_pgp

Implémentation pédagogique en Python 3.9 ou supérieur, sans dépendance externe :
XOR, AES-128/192/256, RSA, PGP-XOR et PGP-AES. Les algorithmes sont répartis en
modules ; l'interface assure la validation des arguments et les entrées/sorties.
Les erreurs sont écrites sur stderr avec le code 84 ; le succès retourne 0.

Le [guide des compétences](COMPETENCES.md) relie les quatre objectifs au code,
aux preuves de fonctionnement et aux notions à expliquer à l'oral.
Le [cours](App.md) présente progressivement les algorithmes.

## Construire et vérifier

```sh
make
./my_pgp -h
make tests_run
make benchmark
python3 bonus/demo_security.py
```

`make` crée un lanceur qui exécute `src/my_pgp.py` ; conserver `src` à côté.
`clean`, `fclean` et `re` permettent de nettoyer et reconstruire le projet.
Le benchmark et les démonstrations de sécurité sont dans `bonus/`.

## Interface

```text
./my_pgp CRYPTO_SYSTEM -c [-b] key
./my_pgp CRYPTO_SYSTEM -d [-b] key
./my_pgp rsa -g P Q
```

Le clair entre sous forme d'octets sur stdin, le chiffré sous forme hexadécimale.
Le chiffrement produit de l'hexadécimal suivi d'un LF. Le déchiffrement en flux
symétrique/hybride écrit les octets directement, sans ajouter de LF.

| Système | Clé | Taille du bloc clair avec `-b` |
| --- | --- | --- |
| `xor` | Hexadécimal, longueur quelconque non nulle | Taille de la clé |
| `aes` | 16, 24 ou 32 octets hexadécimaux | Toujours 16 octets |
| `rsa` | `exposant-module`, entiers little-endian | Un entier inférieur au module |
| `pgp-xor` | `clé_XOR:clé_RSA` | Taille de la clé XOR |
| `pgp-aes` | `clé_AES_128:clé_RSA` | 16 octets |

Avec `-d` hybride, remplacer la clé symétrique par sa version chiffrée par RSA.
Le format hybride fixe AES à 128 bits : la longueur de la clé n'est pas transmise.
AES-192/256 sont disponibles avec le système `aes`. Contrairement à AES-128,
leur taille de clé diffère de la taille de bloc ; `-b` traite toujours 16 octets.

En mode bloc, le LF final éventuel est retiré à l'entrée, les autres LF sont
refusés, et le déchiffrement ajoute un LF. RSA suit cette convention même sans
`-b`. En flux, les octets du clair, y compris les LF et NUL, sont conservés.
Le dernier bloc symétrique incomplet est complété avec des zéros. Ceux-ci sont
conservés après déchiffrement : leur suppression détruirait les NUL réels.

## Exemples du sujet

```sh
printf 'You know nothing, Jon Snow\n' |
  ./my_pgp xor -c -b 576861742069732064656164206d6179206e6576657220646965
# 20070f2700071c6a4449060a490515164e4e12190b190011063c

printf 'All men must die\n' |
  ./my_pgp aes -c -b 57696e74657220697320636f6d696e67
# 744ce22c385958348f0df26eceb62eef

printf '744ce22c385958348f0df26eceb62eef\n' |
  ./my_pgp aes -d -b 57696e74657220697320636f6d696e67
# All men must die

./my_pgp rsa -g d3 e3
# public key: 0101-19bb
# private key: 9d5b-19bb
printf 'WF\n' | ./my_pgp rsa -c 0101-19bb
# 8f84
printf '8f84\n' | ./my_pgp rsa -d 9d5b-19bb
# WF

printf 'AB\n' | ./my_pgp pgp-xor -c -b 5746:0101-19bb
# 8f84
# 1507
printf '1507\n' | ./my_pgp pgp-xor -d -b 8f84:9d5b-19bb
# AB
```

### PGP-AES : exemple reproductible

```sh
P=4b1da73924978f2e9c1f04170e46820d648edbee12ccf4d4462af89b080c86e1
Q=bb3ca1e126f7c8751bd81bc8daa226494efb3d128f72ed9f6cacbe96e14166cb
./my_pgp rsa -g "$P" "$Q" > /tmp/my-pgp.keys
PUBLIC=$(sed -n 's/^public key: //p' /tmp/my-pgp.keys)
PRIVATE=$(sed -n 's/^private key: //p' /tmp/my-pgp.keys)
printf 'All men must die\n' |
  ./my_pgp pgp-aes -c -b "57696e74657220697320636f6d696e67:$PUBLIC" > /tmp/my-pgp.cipher
# Première ligne : clé AES chiffrée ; deuxième ligne : message chiffré.
ENCRYPTED_KEY=$(head -n 1 /tmp/my-pgp.cipher)
tail -n 1 /tmp/my-pgp.cipher |
  ./my_pgp pgp-aes -d -b "$ENCRYPTED_KEY:$PRIVATE"
# All men must die
rm -f /tmp/my-pgp.keys /tmp/my-pgp.cipher
```

Ces premiers publics sont des données de test, pas des clés secrètes.

### Flux binaire

```sh
python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256)))' > /tmp/my-pgp.bin
./my_pgp aes -c 000102030405060708090a0b0c0d0e0f < /tmp/my-pgp.bin > /tmp/my-pgp.hex
./my_pgp aes -d 000102030405060708090a0b0c0d0e0f < /tmp/my-pgp.hex > /tmp/my-pgp.clear
cmp /tmp/my-pgp.bin /tmp/my-pgp.clear
# Identiques : 256 est un multiple de 16, donc aucun remplissage.
rm -f /tmp/my-pgp.bin /tmp/my-pgp.hex /tmp/my-pgp.clear
```

## Modules et conventions

- `src/my_pgp.py` : CLI et registre de sélection des systèmes.
- `src/xor.py` : XOR, inversion de chaque bloc, remplissage nul.
- `src/aes.py` : S-box, expansion de clé, transformations AES et inverses.
- `src/rsa.py` : parsing little-endian, Carmichael, inverse modulaire et `pow`.
- `src/hybrid.py` : composition commune RSA + primitive symétrique.
- `src/pgp_xor.py` et `src/pgp_aes.py` : configuration des deux compositions.

Chaque primitive fournit `encrypt(data, key, block_mode=False)` et `decrypt(...)`.
Les fonctions manipulent des `bytes` ; la CLI s'occupe de l'hexadécimal.
Le chiffrement hybride renvoie `(clé_chiffrée, message_chiffré)`.

Pour reproduire le vecteur AES du sujet, l'adaptateur inverse les octets de la
clé et du chiffré par mots de quatre octets. Le cœur AES est standard et testé
séparément avec des vecteurs connus. RSA encode chaque entier en little-endian,
avec la longueur minimale d'au moins un octet.

RSA perd donc les NUL terminaux du clair. En PGP-AES, la longueur fixe permet de
restaurer la clé sur 16 octets. En PGP-XOR bloc, la taille du chiffré fournit la
longueur. En PGP-XOR flux, les clés de plusieurs octets terminées par NUL sont
refusées au chiffrement : leur longueur serait irrécupérable avec ce format.

## Propriétés et limites

Le projet suit les conventions pédagogiques du sujet : XOR répété, AES par
blocs indépendants de type ECB, RSA sans padding. Il ne fournit ni
authentification des messages ni authentification des clés publiques.
La combinaison hybride conserve ces limites. Voir les démonstrations et
l'analyse détaillée dans [COMPETENCES.md](COMPETENCES.md).

AES est spécifié par [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final).
Les modes de chiffrement sont décrits par
[NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final),
l'authentification GCM par
[NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final),
et RSA-OAEP par [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017).
