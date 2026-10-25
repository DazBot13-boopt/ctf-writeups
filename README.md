# CTF Writeups

Write-ups personnels de plusieurs CTF, organisés par événement puis par catégorie.
Les vrais flags sont **caviardés** (`CTF{REDACTED}`) — ils ont été soumis aux plateformes
autorisées et ne figurent pas ici.

## battleCTF — bugpwn (`ctf.bugpwn.com`)

### Web
- [SwiftNotes](battleCTF-bugpwn/web/swiftnotes.md) — prototype pollution → RCE EJS
- [WireVault](battleCTF-bugpwn/web/wirevault.md) — timing d'auth + fuite de cache / race condition

### Pwn
- [PWN#001](battleCTF-bugpwn/pwn/pwn001.md) — stack overflow, canary leak, ret2libc (x86-64)
- [PWN#002 — Notes](battleCTF-bugpwn/pwn/pwn002-notes.md) — allocateur maison / heap UAF
- [PWN#003 — Notes Vault](battleCTF-bugpwn/pwn/pwn003.md) — UAF, freelist poisoning, ret2libc
- [PWN#004 — Pets](battleCTF-bugpwn/pwn/pwn004-pets.md) — C++ vtable whitelist / heap
- [PWN#005 — Document Store](battleCTF-bugpwn/pwn/pwn005.md) — blind pwn, dump PIE/libc → ORW
- [PWN#Alpha / PWN#Beta — Vault](battleCTF-bugpwn/pwn/vault-alpha-beta.md) — canary leak + ROP (ARM/Thumb & MIPS)

### OT / ICS
- [OT#001 — Water Treatment](battleCTF-bugpwn/ot/ot001.md) — abus de registres Modbus/TCP
- [OT#004 — Chemical Reactor](battleCTF-bugpwn/ot/ot004-chemical-reactor.md) — bypass du SIS via session partagée (protocole OPC-UA-style custom)

### Vuln Research
- [VULN#001 — metadata service](battleCTF-bugpwn/vuln-research/vuln001-libexif.md) — libexif, OOB read MakerNote
- [VULN#003 — DNS inspection](battleCTF-bugpwn/vuln-research/vuln003-cares.md) — c-ares, OOB read parseur CAA
- [VULN#005 — Acme Gateway](battleCTF-bugpwn/vuln-research/vuln005-goahead.md) — GoAhead, BF1 Basic-Auth bypass + leak config

## CTF L'AUTEL (`13.63.167.233.nip.io`)
- [El Diez](ctf-lautel/el-diez.md) · [notes](ctf-lautel/el-diez-notes.md) — web
- [Backend](ctf-lautel/backend.md) — web
- [Le Relais](ctf-lautel/le-relais.md) — forensics
- [Le Passeur](ctf-lautel/le-passeur.md) — IA / défi final

## cruXipher 2026 (`cruxipher.crux-bphc.com`)
- [Internal Affairs](cruxipher2026/internal-affairs.md) — web (GraphQL filter oracle)
- [Puffer](cruxipher2026/puffer.md) — misc (PUF / ML modeling)
- [Wait For It](cruxipher2026/wait-for-it.md) — misc

## Compendium
- [COMPENDIUM.md](COMPENDIUM.md) — compilation de tous les défis (document unique, flags caviardés)
