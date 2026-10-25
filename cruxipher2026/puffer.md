# puffer — cruXipher 2026 (misc)

- **Challenge :** puffer (id 17, misc, 100 pts)
- **Cible :** `https://puffer.cruxipher.crux-bphc.com`
- **Flag :** `FLAG{REDACTED}` (soumis, validé)
- **Statut :** résolu

## Contexte

Le service se présente comme *AuthStorm*, un « device » d'authentification matériel :
« No RAM. No stored keys. No exploitation. » Le handout contient des « shreds » :
39 fichiers `strips/1.txt … strips/39.txt`, chacun composé de 50 000 lignes d'un seul caractère.

Le site expose une page de vérification et une doc cachée dans `robots.txt` :

- `GET /generate` → token JWT avec `pow_challenge` et `difficulty` ;
- `POST /challenge` `{token, solution}` → JWT `{verified, challenge (64b)}` ;
- `POST /response` `{token, response (64b)}` → vérifie la réponse.

`/docs.md` renvoie aussi vers un schéma : `device.png`.

## Reconnaissance

### Réassemblage des shreds

Chaque fichier est une **colonne** du document original. En concaténant la i-ème ligne
de chaque fichier dans l'ordre 1..39, on obtient un fichier parfaitement régulier de
50 000 lignes :

```text
0x3d52bc0ea438a096, 0xb1ee54a30d035f
0x9fa8a46549af2b1e, 0xbfd0acdcb9fa2f63
...
```

Soit 50 000 paires de valeurs 64 bits : des **CRPs** (challenge, response).

### Le device

Le schéma `device.png` montre un multiplexeur contrôlé par le challenge, un signal
`pulse`, puis un `arbiter`. Le nom du module paramétré est un hash Yosys
(`$paramod$…\switch_line`) : c'est un **arbiter PUF**, ici avec un challenge 64 bits
et une réponse 64 bits (64 arbitres parallèles).

Un arbiter PUF est modélisable : chaque bit de réponse est le signe d'une combinaison
linéaire de produits de parité des bits du challenge.

## Exploitation

### Features de parité

Pour un challenge `c` :

```text
s_i   = 1 - 2*c_i
phi_i = prod_{j<=i} s_j      (produits préfixes)
phi_64 = 1                   (biais)
```

Chaque bit de réponse `r_j` vaut `1` si `w_j · phi > 0`.

### Apprentissage

Avec les 50 000 CRPs, une régression aux moindres carrés par bit retrouve les poids :

```python
W = np.zeros((65, 64))
for j in range(64):
    y = (((Y >> np.uint64(j)) & 1).astype(np.float64)) * 2 - 1
    W[:, j] = np.linalg.lstsq(F, y, rcond=None)[0]
```

Précision mesurée sur 10 000 CRPs de test : **~98,97 % par bit** (la convention
« suffixe » ou les bits bruts plafonnent à ~50 %). Le PUF simulé a donc un peu de bruit :
la probabilité que les 64 bits soient exacts est d'environ `0,99^64 ≈ 0,5`.

### Soumission

Le solveur (`cruxipher2026/exploits/puffer.py`) :

1. `GET /generate`, résout le PoW (SHA-256 avec `difficulty` zéros hex) ;
2. `POST /challenge` pour obtenir le challenge courant ;
3. prédit la réponse 64 bits et l'envoie à `/response` au format `0x%016x` ;
4. recommence avec un nouveau challenge en cas d'échec (bruit du PUF).

Au premier essai :

```text
attempt 0 challenge 0xefd7ef3949bcae15 resp 0x41a71367d6ab78ca
-> {'error': False, 'message': 'Response Verified!', 'flag': 'FLAG{REDACTED}'}
```

## Leçons

- Les « shreds » sont des colonnes : un simple réassemblage colonne par colonne suffit.
- Un schéma de circuit + des CRPs = attaque par apprentissage ; inutile de chercher une
  faille logicielle dans le service.
- La convention des features (préfixe vs suffixe) est le point critique.
- Un PUF bruité se contourne en réessayant avec de nouveaux challenges.

## Références

- Fiche knowledge : `knowledge/misc/arbiter-puf-ml-modeling.md`
- Solveur : `cruxipher2026/exploits/puffer.py`
