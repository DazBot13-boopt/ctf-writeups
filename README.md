# battleCTF — bugpwn writeups

Write-ups des challenges du CTF **bugpwn** (`https://ctf.bugpwn.com`, plateforme battleCTF),
organisés par catégorie. Les vrais flags sont **caviardés** (`CTF{REDACTED}`) — ils ont été
soumis à la plateforme et ne figurent pas ici.

## Web
- [SwiftNotes](web/swiftnotes.md) — prototype pollution → RCE EJS
- [WireVault](web/wirevault.md) — timing d'auth + fuite de cache / race condition
- [TicketVault](web/ticketvault.md) — injection de filtre NoSQL → broken access control (IDOR)
- [ClearHouse](web/clearhouse.md) — IDOR GraphQL + path traversal + js-yaml v3 RCE via toJSON
- [EchoGate](web/echogate.md) — HTTP request smuggling CL.TE → accès admin interne

## Pwn
- [PWN#001](pwn/pwn001.md) — stack overflow, canary leak, ret2libc (x86-64)
- [PWN#002 — Notes](pwn/pwn002-notes.md) — allocateur maison / heap UAF
- [PWN#003 — Notes Vault](pwn/pwn003.md) — UAF, freelist poisoning, ret2libc
- [PWN#004 — Pets](pwn/pwn004-pets.md) — C++ vtable whitelist / heap
- [PWN#005 — Document Store](pwn/pwn005.md) — blind pwn, dump PIE/libc → ORW
- [PWN#006 — QuickJS](pwn/pwn006-quickjs.md) — TypedArray OOB bounds-check bypass → arbitrary read → environ leak
- [PWN#Delta — Vault PPC](pwn/pwn-delta.md) — off-by-one canary leak + stwu back-chain ROP (PowerPC32)
- [PWN#Alpha / PWN#Beta — Vault](pwn/vault-alpha-beta.md) — canary leak + ROP (ARM/Thumb & MIPS)
- [PWN#Epsilon — Vault RISC-V 64](pwn/pwn-epsilon.md) — canary leak + ROP syscall `execve` (`c.ldsp`/`addi16sp`)

## OT / ICS
- [OT#001 — Water Treatment](ot/ot001.md) — abus de registres Modbus/TCP
- [OT#002 — Breaker 52](ot/ot002-breaker52.md) — protocole binaire custom, attaque Aurora (fermeture hors synchronisme)
- [OT#003 — Furnace Portal](ot/ot003-furnace-portal.md) — credential leak + SSRF filter bypass (case-sensitivity, IP encoding) + vessel rupture
- [OT#004 — Chemical Reactor](ot/ot004-chemical-reactor.md) — bypass du SIS via session partagée (protocole OPC-UA-style custom)

## Vuln Research
- [VULN#001 — metadata service](vuln-research/vuln001-libexif.md) — libexif, OOB read MakerNote
- [VULN#002 — DHCPv6 relay](vuln-research/vuln002-dnsmasq.md) — dnsmasq, heap-buffer-overflow read in DHCPv6 relay
- [VULN#003 — DNS inspection](vuln-research/vuln003-cares.md) — c-ares, OOB read parseur CAA
- [VULN#004 — Ghost-Pixel](vuln-research/vuln004-ghostpixel.md) — giflib 5.2.2, double-free in decode cleanup
- [VULN#005 — Acme Gateway](vuln-research/vuln005-goahead.md) — GoAhead, BF1 Basic-Auth bypass + leak config
- [VULN#006 — Font Inspector](vuln-research/vuln006-freetype-bdf.md) — FreeType, heap OOB read via table BDF embarquée

## Out Context
- [Operation BLACKHOLE 1→8](out-context/operation-blackhole.md) — analyse de pcap DDoS (8 questions sur `CTF1.pcapng`)
- [0byte](out-context/0byte.md) — flag meta / trivia
- [Discord](out-context/discord.md) — flag sur le serveur Discord officiel
- [Know Your Enemy](out-context/know-your-enemy.md) — OSINT sur l'empreinte publique de BUG|PWN
