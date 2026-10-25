# battleCTF — bugpwn writeups

Write-ups des challenges du CTF **bugpwn** (`https://ctf.bugpwn.com`, plateforme battleCTF),
organisés par catégorie. Les vrais flags sont **caviardés** (`CTF{REDACTED}`) — ils ont été
soumis à la plateforme et ne figurent pas ici.

## Web
- [SwiftNotes](web/swiftnotes.md) — prototype pollution → RCE EJS
- [WireVault](web/wirevault.md) — timing d'auth + fuite de cache / race condition

## Pwn
- [PWN#001](pwn/pwn001.md) — stack overflow, canary leak, ret2libc (x86-64)
- [PWN#002 — Notes](pwn/pwn002-notes.md) — allocateur maison / heap UAF
- [PWN#003 — Notes Vault](pwn/pwn003.md) — UAF, freelist poisoning, ret2libc
- [PWN#004 — Pets](pwn/pwn004-pets.md) — C++ vtable whitelist / heap
- [PWN#005 — Document Store](pwn/pwn005.md) — blind pwn, dump PIE/libc → ORW
- [PWN#006 — QuickJS](pwn/pwn006-quickjs.md) — TypedArray OOB bounds-check bypass → arbitrary read → environ leak
- [PWN#Alpha / PWN#Beta — Vault](pwn/vault-alpha-beta.md) — canary leak + ROP (ARM/Thumb & MIPS)

## OT / ICS
- [OT#001 — Water Treatment](ot/ot001.md) — abus de registres Modbus/TCP
- [OT#004 — Chemical Reactor](ot/ot004-chemical-reactor.md) — bypass du SIS via session partagée (protocole OPC-UA-style custom)

## Vuln Research
- [VULN#001 — metadata service](vuln-research/vuln001-libexif.md) — libexif, OOB read MakerNote
- [VULN#002 — DHCPv6 relay](vuln-research/vuln002-dnsmasq.md) — dnsmasq, heap-buffer-overflow read in DHCPv6 relay
- [VULN#003 — DNS inspection](vuln-research/vuln003-cares.md) — c-ares, OOB read parseur CAA
- [VULN#005 — Acme Gateway](vuln-research/vuln005-goahead.md) — GoAhead, BF1 Basic-Auth bypass + leak config

---

### Non inclus (pas de write-up disponible)
Résolus sur la plateforme mais sans write-up exploitable : **OT#002, OT#003, PWN#Delta**.
Les challenges « out context » (0byte, Discord, Know Your Enemy, Operation BLACKHOLE 1→8) ne sont pas documentés ici.
