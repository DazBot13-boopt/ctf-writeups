# OT-004 — Chemical Reactor (OPC-UA-style custom TCP)

## Cible
- Page : https://otctf.pages.dev/ot-004-chemical-reactor/
- Service : `169.58.126.107:6003`
- Catégorie : OT
- Objectif : neutraliser le Safety Instrumented System (SIS), qui partage le **même
  address space / même session** que le process controller, puis pousser le réacteur
  en condition dangereuse **soutenue**. Format `CTF{REDACTED}`.
- Modèle annoncé : OPC-UA-style, nœud racine `Objects (ns=0, id=85)`. Address space =
  `Objects` → `Reactor Controller` (process tags) + `Safety System` (trip/protection).
  « discover them by talking to the endpoint ». NO SOURCE / NO BINARY / NO MAP.

## FAITS confirmés (reproductibles)

### Transport
- TCP ouvert, **pas de bannière** : le serveur attend que le client parle.
- **Ce n'est PAS de l'OPC UA binaire réel** : un HEL OPC UA (`HELF`+size LE+body),
  via client manuel *et* via `asyncua`, provoque une fermeture immédiate (« socket closed »).
- Framing = **`[uint32 big-endian longueur][payload]`**, longueur = taille du payload
  (hors en-tête). Prouvé :
  - `len=8` puis 3 octets → connexion vivante (attend 5 de plus) ; après 8 octets → traité.
  - `len=4` en-tête seul → vivant (attend 4 octets).
  - `len=0` (trame vide) → **vivant** : no-op, le serveur reboucle lire la trame suivante.
  - 5 octets `AAAAA` → fermeture (len=0x41414141 ≈ 1 Go > cap max → rejet).
  - `HELF...` ferme pour la même raison (0x48454c46 lu comme longueur).
- Cap de longueur max (valeur exacte non mesurée ; grandes longueurs → close).

### Couche message (payload) — INCONNUE, aucun oracle
- Le serveur **ferme en silence** sur toute trame complète invalide ; **ne répond jamais**
  (aucune donnée reçue, ni avant ni après `shutdown(SHUT_WR)`).
- `len=1` quel que soit l'octet → close. Seule la trame `len=0` est tolérée.
- Testé sans succès (tous → close) :
  - Texte brut framé : `hello`, `HELLO`, `HEL`, `Hello`, `Hello\n`, `Read`, `Browse`,
    `Write`, `PING`, `VERSION\n`, `LIST\n`, `READ 85\n`, `BROWSE 85\n`, `WRITE 85 1\n`,
    `HELLO 1\n`, `browse ns=0;i=85`.
  - JSON framé : `{"op":"hello"}`, `{"type":"hello"}`, `{"type":"Hello"}`,
    `{"op":"browse","node":"ns=0;i=85"}`, `{"a":1}`, etc.
  - Binaire framé : opcodes 0x00–0x09 + `u32be(85)` ; mono-octets 0x01-0x04/'H'/'B'/'R'/'W'/'L' ;
    `HEL`/`HELF` + corps OPC UA ; NodeId OPC UA 2-byte `00 55`.
- **Faux positif noté** : un mono-octet `0x52` ('R') a semblé « vivant » une fois, mais
  non reproductible (close ensuite). Les « alive » = read-timeouts ne sont **pas fiables**
  (le serveur tarde parfois à envoyer le FIN) → seul un **DATA reçu** compterait comme succès.

### Rate-limit / ban
- ~20 connexions rapides (≈10/min) → ban (EOF immédiat sur tout, même passif).
- Levé après ~8 min de silence total.
- ~5/min (12 s d'écart) : tenable sur 10+ connexions sans ban.

## MUR actuel
Framing entièrement caractérisé, mais la **couche message est inconnue et le serveur ne
donne aucun feedback** (ni réponse, ni message d'erreur). Le brute-force aveugle de la
structure du payload n'est pas tractable en un nombre raisonnable de connexions
(espacement imposé + ban), et sans binaire/source ni capture.

## Pistes pour débloquer
1. Obtenir le **binaire/source/un client fourni** ou une **capture pcap** d'un échange
   légitime → reconstituer le format du payload.
2. Vérifier si la plateforme fournit ailleurs un client/exemple pour ce protocole.
3. Scan exhaustif (lent, ban-prone) de la structure du payload en ne retenant que les
   trames qui renvoient de la **data**.

## Outils
- venv asyncua : `scratchpad/venv/bin/python` (asyncua 2.1.0).
- Scripts de sonde : `scratchpad/*.py` (framing prouvé dans `frame.py`, `sem.py`).

## RÉSOLU

Protocole réel (non deviné à l'aveugle — fourni) : **`[op:u8][len:u32 LITTLE-endian][payload]`**.
Mon erreur bloquante : avoir lu le 1er octet comme une longueur **big-endian** (c'est l'opcode).

- `0x01` handshake (payload vide) → `0x81` + session id (u32le).
- `0x03` read : payload `<IHI sid,ns,nid>` → body `u32 | status:u8 | type:u8 | value`.
- `0x04` write : payload `<IHI sid,ns,nid> + type:u8 + value` → status à body[4].
- types : 1=i32, 2=f64, 3=bool, 4=string.

**Nœuds clés :** `(1,1001)` HeaterPower f64, `(1,1002)` Temp, `(1,1003)` Pressure,
`(2,2001)` TripEnable bool (SIS), `(2,2008)` PretripLatch bool (SIS),
`(2,2003)` Tripped, `(2,2004)` Flag (string).

**Faille :** le SIS « indépendant » est **inscriptible via la même session** que le controller
(même address space, mêmes op génériques). On écrit `TripEnable=False` + `PretripLatch=False`
→ la protection ne déclenche plus → `HeaterPower=100.0` → runaway soutenu (T monte sans trip)
→ le flag apparaît en `(2,2004)`.

Flag (caviardé) : `CTF{REDACTED}` — récupéré, à soumettre par l'utilisateur.
Solver : `challenges/ot-004-chemical-reactor/solve.py`.
