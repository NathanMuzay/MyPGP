# Cours sur les systèmes de chiffrement de my_pgp

Dans ce projet, tu as utilisé **XOR, AES-128/192/256, RSA, PGP-XOR et PGP-AES**. Ils permettent tous de chiffrer des données, mais ils ne gèrent pas les clés de la même manière.

Pour comprendre leur fonctionnement, on va partir des bases puis suivre ce que fait ton code.

## 1. Les bases du chiffrement

Le **message clair** est le message original. Le **message chiffré** est le résultat du chiffrement. La **clé** est la donnée qui permet de réaliser l'opération.

```text
Message clair + clé → chiffrement → message chiffré
Message chiffré + clé → déchiffrement → message clair
```

Il existe deux grandes familles :

| Famille | Principe | Dans ton projet |
| --- | --- | --- |
| Symétrique | La même clé sert à chiffrer et déchiffrer | XOR, AES |
| Asymétrique | Une clé publique et une clé privée sont utilisées | RSA |

Avec un système symétrique, les deux personnes doivent connaître la clé secrète. Le problème est donc de **transmettre cette clé sans la révéler**.

Avec RSA, une personne peut partager sa clé publique et garder sa clé privée secrète.

## 2. XOR : combiner les bits

XOR, appelé « OU exclusif », est une opération qui compare deux bits :

| Premier bit | Deuxième bit | Résultat XOR |
| --- | --- | --- |
| 0 | 0 | 0 |
| 0 | 1 | 1 |
| 1 | 0 | 1 |
| 1 | 1 | 0 |

**Le résultat vaut 1 lorsque les deux bits sont différents.**

En Python, cette opération s'écrit avec `^`.

### Chiffrer un octet

Prenons la lettre `A`, représentée par l'octet `0x41`, et la clé `0x03` :

```text
A       : 01000001
Clé     : 00000011
          --------
Chiffré : 01000010
```

Le résultat est `0x42`.

Pour déchiffrer, on applique à nouveau la même clé :

```text
Chiffré : 01000010
Clé     : 00000011
          --------
Clair   : 01000001
```

Cela fonctionne grâce à la propriété :

```text
(message XOR clé) XOR clé = message
```

### Dans ton code

Dans `src/xor.py`, ton programme :

1. Découpe le message en blocs de la taille de la clé.
2. Complète le dernier bloc avec des zéros si nécessaire.
3. Inverse les octets de chaque bloc.
4. Applique XOR entre le bloc inversé et la clé.

Exemple avec `AB` et la clé `0102` :

```text
Message             : 41 42
Message inversé     : 42 41
Clé                 : 01 02
Résultat XOR        : 43 43
```

Au déchiffrement, il applique XOR puis inverse les octets pour retrouver `AB`.

**L'inversion des octets est une convention de ton projet ; elle n'est pas nécessaire au principe du XOR.**

### Limite du XOR

XOR est simple et rapide, mais réutiliser la même clé révèle des relations entre les messages :

```text
C1 = M1 XOR K
C2 = M2 XOR K

C1 XOR C2 = M1 XOR M2
```

La clé disparaît de cette dernière opération.

XOR peut servir à construire un masque jetable sûr si la clé est aléatoire, aussi longue que le message, secrète et utilisée une seule fois. La clé répétée de ton programme ne remplit pas ces conditions.

## 3. AES : transformer des blocs

AES est un algorithme symétrique : **la même clé secrète sert au chiffrement et au déchiffrement**.

Dans AES-128 :

- la clé fait **128 bits**, donc **16 octets** ;
- chaque bloc de message fait aussi **16 octets** ;
- le chiffrement utilise **10 tours** de transformations.

Le projet prend aussi en charge AES-192 et AES-256 : clés de 24 et 32 octets, avec 12 et 14 tours. Le bloc reste toujours de 16 octets. Le déroulement à dix tours ci-dessous décrit AES-128.

Les 16 octets du bloc sont organisés dans une matrice de quatre lignes et quatre colonnes, appelée **état**.

### Les transformations

**AddRoundKey** combine l'état avec une clé de tour grâce à XOR.

**SubBytes** remplace chaque octet par un autre à l'aide d'une table appelée S-box. Cette transformation apporte la non-linéarité : les relations entre entrée et sortie ne se réduisent plus à de simples opérations XOR.

**ShiftRows** décale les lignes de la matrice. Cela déplace les octets vers différentes colonnes.

**MixColumns** mélange les octets de chaque colonne. Avec les autres transformations, cela propage l'influence d'un octet sur plusieurs octets du résultat.

### Le déroulement du chiffrement

```text
Bloc clair
    ↓
AddRoundKey initial
    ↓
9 tours :
    SubBytes
    ShiftRows
    MixColumns
    AddRoundKey
    ↓
Dernier tour :
    SubBytes
    ShiftRows
    AddRoundKey
    ↓
Bloc chiffré
```

Le dernier tour ne contient pas `MixColumns`.

La fonction `_expand_key()` de ton code transforme la clé initiale en **11 clés de tour pour AES-128** : une pour l'opération initiale, puis une pour chacun des dix tours. AES-192 et AES-256 utilisent respectivement 13 et 15 clés de tour.

Le déchiffrement applique les transformations inverses avec les clés dans l'ordre inverse.

### Dans ton projet

Dans `src/aes.py`, tu as deux niveaux :

- `_encrypt_block()` et `_decrypt_block()` réalisent les opérations AES sur un bloc ;
- `encrypt()` et `decrypt()` gèrent le découpage, le remplissage et les conversions d'octets.

Ton interface inverse les octets de la clé et du chiffré **par groupes de quatre octets**. Cette convention de représentation est distincte du fonctionnement du cœur AES.

### Pourquoi le mode d'utilisation compte

AES ne définit pas, à lui seul, comment traiter un message de plusieurs blocs.

Dans ton programme, les blocs sont chiffrés indépendamment, selon un fonctionnement de type ECB :

```text
Même bloc clair + même clé → même bloc chiffré
```

Des répétitions du message peuvent donc rester visibles sous forme de répétitions dans le chiffré. En pratique, on utilise des modes adaptés, par exemple AES-GCM, qui permet aussi de vérifier l'intégrité des données.

## 4. RSA : une paire de clés

RSA est asymétrique :

- la **clé publique** peut être partagée ;
- la **clé privée** doit rester secrète.

Pour envoyer un message à quelqu'un, on le chiffre avec **sa clé publique**. Il le déchiffre avec **sa clé privée**.

### Construire les clés

On choisit deux nombres premiers distincts, `p` et `q`.

Ton programme calcule :

```text
n = p × q
λ(n) = ppcm(p − 1, q − 1)
```

`n` est le module. Le PPCM est le plus petit multiple commun.

On choisit ensuite un exposant public `e` premier avec `λ(n)` :

```text
pgcd(e, λ(n)) = 1
```

Puis on calcule l'exposant privé `d`, qui vérifie :

```text
e × d ≡ 1 modulo λ(n)
```

Les clés sont :

```text
Clé publique : (e, n)
Clé privée   : (d, n)
```

### Exemple avec de petits nombres

Prenons :

```text
p = 5
q = 11

n = 55
λ(n) = ppcm(4, 10) = 20
```

Ton programme choisit ici `e = 17`.

L'exposant privé est `d = 13`, car :

```text
17 × 13 = 221
221 modulo 20 = 1
```

On obtient :

```text
Clé publique : (17, 55)
Clé privée   : (13, 55)
```

### Chiffrer et déchiffrer

Le message est représenté par un entier `m`, avec `0 ≤ m < n`.

Les opérations sont :

```text
Chiffrement   : c = mᵉ modulo n
Déchiffrement : m = cᵈ modulo n
```

Pour `m = 2` :

```text
c = 2¹⁷ modulo 55 = 7
m = 7¹³ modulo 55 = 2
```

Dans ton code, ces calculs sont effectués avec :

```python
pow(value, exponent, modulus)
```

Cette fonction calcule la puissance modulo `n` efficacement.

### Dans ton projet

`src/rsa.py` convertit le message en entier **little-endian**, puis applique RSA.

Le message entier doit être inférieur au module. RSA ne découpe donc pas automatiquement un long fichier en blocs.

Ton implémentation utilise RSA **sans padding**. Pour une utilisation réelle, un mécanisme comme OAEP est nécessaire : RSA brut est déterministe et ne protège pas correctement les messages.

## 5. PGP-XOR : le chiffrement hybride

PGP-XOR combine :

- un chiffrement symétrique pour le message ;
- un chiffrement asymétrique pour la clé symétrique.

### Chiffrement

```text
Message + clé XOR
    → XOR
    → message chiffré

Clé XOR + clé publique RSA
    → RSA
    → clé XOR chiffrée
```

On transmet les deux résultats.

### Déchiffrement

```text
Clé XOR chiffrée + clé privée RSA
    → RSA
    → clé XOR récupérée

Message chiffré + clé XOR récupérée
    → XOR
    → message clair
```

L'intérêt est de pouvoir transmettre la clé symétrique sous forme chiffrée. Le destinataire la récupère avec sa clé privée.

### Dans ton code

Dans `src/pgp_xor.py`, le chiffrement est essentiellement :

```python
encrypted_key = rsa.encrypt(symmetric, asymmetric)
encrypted_message = xor.encrypt(data, symmetric, block_mode)
```

Le déchiffrement fait les opérations correspondantes :

```python
symmetric = rsa.decrypt(encrypted_key, asymmetric)
message = xor.decrypt(data, symmetric, block_mode)
```

Ces extraits résument les appels principaux. En mode bloc, le code restaure aussi les éventuels octets nuls terminaux de la clé récupérée avec RSA avant d'appeler XOR.

Ton format est propre au projet : il ne correspond pas à un fichier OpenPGP standard. La combinaison avec RSA ne corrige pas les limites du XOR répété ni celles du RSA sans padding.

**PGP-AES** est implémenté avec le même principe, en utilisant AES-128 pour le message. Les deux compositions partagent maintenant `src/hybrid.py`. La longueur fixe de 16 octets permet de restaurer les NUL terminaux de la clé AES après RSA.

## 6. Hexadécimal, little-endian et remplissage

Ces notions concernent la représentation des données. Elles ne sont pas des algorithmes de chiffrement.

### Hexadécimal

Un octet est représenté par deux chiffres hexadécimaux :

```text
A → octet 65 en décimal → 41 en hexadécimal
```

Afficher `A` sous la forme `41` est un encodage réversible sans clé.

### Little-endian

Le little-endian place l'octet de poids faible en premier.

Pour le nombre `0x1234` :

```text
Big-endian    : 12 34
Little-endian : 34 12
```

Ton module RSA utilise cet ordre pour convertir les octets en nombres et inversement.

### Remplissage par zéros

Si un bloc attend quatre octets et qu'il en reste trois :

```text
Avant : 41 42 43
Après : 41 42 43 00
```

Ton programme conserve ce zéro après déchiffrement. Il ne connaît pas la longueur d'origine et ne peut donc pas savoir si le zéro appartient au message ou au remplissage.

## 7. Les différences à retenir

| Système | Clés | Traitement | Point essentiel |
| --- | --- | --- | --- |
| XOR | Une clé partagée | Opération bit à bit | Réappliquer la clé annule le XOR |
| AES-128 | Une clé secrète de 16 octets | Blocs de 16 octets | Plusieurs tours de substitutions et de mélanges |
| RSA | Une clé publique et une clé privée | Entiers modulo n | La clé publique chiffre, la privée déchiffre |
| PGP-XOR | Clé XOR et paire RSA | Chiffrement hybride | XOR chiffre le message, RSA protège la clé |
| PGP-AES | Clé AES-128 et paire RSA | Chiffrement hybride | AES chiffre le message, RSA protège la clé |

Pour expliquer ton projet à l'oral, tu peux dire :

> « J'ai implémenté deux chiffrements symétriques, XOR et AES-128, puis RSA pour le chiffrement asymétrique. PGP-XOR les combine : le message est chiffré avec XOR et la clé XOR avec RSA. L'interface gère les arguments, les conversions hexadécimales, les blocs et les entrées/sorties. »

Pour relier ces explications aux quatre compétences et aux preuves de fonctionnement, consulter [COMPETENCES.md](COMPETENCES.md).
