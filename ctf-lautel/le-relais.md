# Le Relais — CTF L'AUTEL (forensics, 500 pts)

## Résumé
Analyse d'une capture PCAP (`relais.pcap`) d'un serveur relais (`relais/2.7` sur `centre-controle.interne`). Objectif : reconstituer les sessions, trouver le canal, assembler le message.

## Chaîne d'attaque

### 1. Analyse du trafic
- 116 paquets, HTTP/JSON sur port 80.
- Endpoints : `/api/journal`, `/api/vues`, `/api/keepalive`, `/metrics`, `/healthz`, `/archives/<année>`, `/journal`.
- En-têtes caractéristiques : `X-Bascule-Seq` (0-7), `X-Rapport` (fragments), `X-Request-Id`, `X-Trace`.
- User-Agent : `agent-relais/3.2`.

### 2. Canal caché
Les fragments dans `X-Rapport` ordonnés par `X-Bascule-Seq` :
| Seq | Fragment |
|-----|----------|
| 0 | `--` |
| 1 | `le_cont` |
| 2 | `re_sign` |
| 3 | `e_passe` |
| 4 | `_chez_l` |
| 5 | `e_passe` |
| 6 | `ur_pas_` |
| 7 | `au_trone` |

Assemblé : `--le_contre_signe_passe_chez_le_passeur_pas_au_trone`
→ **« Le contre-signe se passe chez le Passeur, pas au trône »**

### 3. Flag
Le message reconstitué est le flag (format `AMR{REDACTED}` accepté par le portail) :
`AMR{REDACTED}`

## Soumission
`POST /api/game/api/challenges/le-relais/verifier` → `{"ok":true,"dejaResolu":true}`.
