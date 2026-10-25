# PWN#004 — Pets (C++ / vtable whitelist / heap)

## Statut

Résolu. Flag lu à distance (`cat /flag/flag.txt`) : `CTF{REDACTED}` (soumission laissée à l'utilisateur, jamais stockée dans le dépôt).

## Cible

- Binaire : `pets` (ELF64, PIE, Full RELRO, canary, NX, strippé, C++).
- Service : `169.58.126.107:5007`.
- Libc distante : `libc6_2.43-5/_amd64` (Debian glibc 2.43) — `puts=0x81be0`, `system=0x541b0`.

## Vulnérabilités

- `remove_pet` / `remove_note` libèrent le chunk **sans** remettre le pointeur à `NULL` → **UAF** (lecture/écriture après free).
- `poke_pet` fait `memcpy(pets[idx], buf, n)` (n ≤ 0x20) → **écriture contrôlée de 0x20 octets** sur un objet (y compris dangling).
- Menu option 9 « leak » : `printf("%p\n", *(pets[idx]))` → **fuite du vptr** (donc du PIE).
- Allocateur maison : classes `{0x20,0x40,0x80}`, pool unique `0x4000`, free-list mangée `mangle(a,b)=a ^ rol(b,7)` (rol **7**).

## Vtable whitelist et gadget

- Avant `speak_pet`, le programme vérifie que `obj->vptr` ∈ `{Cat, Dog, Command}` (table en `.data.rel.ro`). Le `Command` vtable est whitelisté.
- Slot 0 du vtable `Command` :
  ```asm
  mov  rax,[rdi+8]
  movabs rcx,0x5f3759df2f2f2f2f
  xor  rax,rcx
  test rax,rax
  je   ...
  add  rdi,0x10
  jmp  rax
  ```
  → `fn = champ[+8] ^ KEY`, appelé avec `rdi = obj+0x10`.

## Chaîne d'exploitation

1. **PIE** : option 9 sur un pet → `vptr`, `pie = vptr - Cat_vtable`.
2. **Heap** : `add_note` + `remove_note` (libère le 1ᵉʳ chunk de classe 0, liste vide → `*N0 = rol(N0,7)`), puis `peek_note` → `N0 = ror(leak,7)`, `pool = N0 - 0x40`.
3. **Freelist poisoning** : `remove_pet(0)` puis `poke_pet(0, p64(T ^ rol(P0,7)))` avec `T = &pets[K]` ; deux `add_pet` rendent `T` → `pets[3] = T`.
4. **Leak libc** : `poke_pet(3, p64(pie+puts@got))` écrit `pets[K] = &puts@got`, option 9 → `puts`, `libc = puts - 0x81be0`.
5. **Forge Command** : `poke_pet` sur un pet vivant =
   `p64(pie+Command_vtable) + p64(system ^ KEY) + b"/bin/sh"`.
6. `speak_pet` → whitelist OK → gadget → `system("/bin/sh")` → `cat /flag/flag.txt`.

## Note locale

Le binaire téléchargé crashe **localement** au démarrage : `e_entry` (0x269e) est un stub obfusqué (`rbx=[0x5010]^MAGIC; add rax,rbx; jmp rax`) et le qword `.data:0x5010` vaut `0xff3759df2f2f2f2f` (au lieu de la valeur attendue) → saut non-canonique → `SIGSEGV`. Le service distant tourne un binaire sain. Pour itérer localement, on patche `e_entry` → `_start` (0x1130) ; le layout (vtables, handlers, allocateur) reste intact.

## Identification de la libc (piège IFUNC)

`memcpy/strchr/memset/strncpy` sont des **IFUNC** : leur GOT contient la variante SIMD résolue, pas l'offset du symbole → deltas inexploitables. En se limitant aux symboles non-IFUNC (`puts/printf/read/write/exit/setvbuf`) et à leurs deltas relatifs à `puts`, libc.rip retourne `libc6_2.43-5/_amd64` (deltas identiques : `printf -0x26e20`, `read +0x848a0`, `write +0x85300`, `exit -0x3efd0`, `setvbuf +0x890`).

## PoC

- `pets_exploit.py` — `python3 pets_exploit.py local` (binaire patché `/tmp/opencode/pets_local`) / `python3 pets_exploit.py remote`.

## Leçons

- Full RELRO n'empêche pas les fuites GOT : combiner leak vptr (PIE) + GOT (libc).
- Toujours vérifier le `rol N` du mangle et les GOT d'IFUNC.
- Un binaire qui crashe au démarrage localement peut très bien tourner à distance : tester `nc` avant de conclure.
