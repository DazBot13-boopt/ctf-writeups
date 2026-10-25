# PWN#002 — Notes (allocateur maison / heap)

## Statut

Résolu. Flag lu à distance : `CTF{REDACTED}` (soumission laissée à l'utilisateur, jamais stockée dans le dépôt).

## Cible

- Binaire : `notes` (ELF64, PIE, Full RELRO, canary, NX, non strippé).
- Service : `169.58.126.107:5002`.

## Vulnérabilité

`free_note` ne remet pas `notes[idx] = NULL` → **UAF** (View/Edit sur un chunk libéré) et double-free possibles.

## Allocateur maison

- 3 classes : `{0x20, 0x40, 0x80}` (pools `void palloc`), au-delà → glibc.
- Pool unique `malloc(0x4000)` + `pool_cursor`.
- Liste libre XOR-mangée : `mangle(a,b)=a ^ rol(b,13)`, key = adresse du nœud.

Structure `note` (`.bss`, base `notes_storage=0x40e0`, stride `0x18`) :
`+0x00 formatter (fn ptr)` · `+0x08 content` · `+0x10 size`.
`view` appelle `formatter(content)`.

## Chaîne d'exploitation

1. **PIE** : `[debug] build id: %p` → `&main` → `pie = leak - main`.
2. **Heap** : free d'une note classe-0 (liste vide) → view lit `rol(node,13)` → `node = ror(leak,13)` (début du pool).
3. **libc** : allocation arbitraire sur la structure d'une note → `{default_formatter, puts@got, size}` → View écrit 32 octets depuis `puts@got` → 4 symboles d'un coup (`puts`, `write`, `__stack_chk_fail`, `printf`). Identification : `libc6_2.42-13_amd64` via libc.rip (low12 : `puts=0x60, write=0xd10, __stack_chk_fail=0x2b0, printf=0x1c0`).
4. **Arbitrary write** : éditer le chunk libéré `N` avec `T ^ rol(N,13)` puis deux `add` de la même classe (le 2ᵉ, après pop de `T`, y écrit notre payload).
5. **Hijack** : écraser une structure note avec `{system, libc+str_bin_sh, 0x40}` puis déclencher `view` → `system("/bin/sh")`.

## Résultats confirmés

- Exploit local : shell sur le binaire local (`id` exécuté).
- Exploit distant : shell (uid `nobody`, cwd `/challenge`), flag lu via `cat /flag/flag.txt`.

## PoC

- `notes_exploit.py` (usage : `python3 notes_exploit.py` en local, `python3 notes_exploit.py remote` contre le service).

## Leçons

- Full RELRO empêche l'écriture GOT mais **pas la lecture** : le GOT reste une excellente source de leaks.
- Créer une note de la même classe après un `free` vole immédiatement le chunk libéré → commande d'abord les allocations avant le `free`.
- Les `read()` du programme consomment tout le buffer du pipe : interaction ligne par ligne obligatoire.