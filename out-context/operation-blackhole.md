# Operation BLACKHOLE 1→8 — Analyse de trafic DDoS (pcap)

- **Catégorie :** out context (forensics réseau)
- **Flag :** réponse directe à chaque question (pas de format `CTF{...}` standard)
- **Fichier fourni :** `CTF1.pcapng` (capture réseau d'un incident DDoS sur Acme Corp)

## Contexte

> *Our subsidiary, Acme Corp, was hit by a DDoS attack last night.
> The SOC team captured the network traffic during the incident.
> Objective: Analyze CTF1.pcapng and answer the 8 questions.*

Les 8 challenges partagent le **même fichier pcap** et posent chacun une question d'analyse
forensique réseau. L'outil principal est **Wireshark** (ou `tshark` en ligne de commande).

## Questions et méthode

### BLACKHOLE 1 (5 pts) — « What is the IP address of the attacking machine? »

Identifier l'IP source qui génère le plus de trafic (flood). Dans Wireshark :
`Statistics → Endpoints → IPv4`, trier par nombre de paquets ou octets.

Flag : `CTF{REDACTED}`

### BLACKHOLE 2 (5 pts) — « What is the target's IP address? »

L'IP de destination principale du flood. Même approche : `Statistics → Conversations → IPv4`,
la paire avec le plus de paquets donne à la fois la source (Q1) et la cible (Q2).

Flag : `CTF{REDACTED}`

### BLACKHOLE 3 (10 pts) — « Which TCP port is targeted by the HTTP attack? »

Filtrer sur l'IP source identifiée en Q1 : `ip.src == <attacker>`. Observer le port de
destination TCP (`tcp.dstport`). Pour un flood HTTP, c'est typiquement 80 ou 8080.

Flag : `CTF{REDACTED}`

### BLACKHOLE 4 (10 pts) — « Which HTTP method is used for flooding? »

Filtre Wireshark : `http.request && ip.src == <attacker>`. Vérifier le champ `http.request.method`.
DDoS HTTP classique : `GET` ou `POST`.

Flag : `CTF{REDACTED}`

### BLACKHOLE 5 (10 pts) — « Which User-Agent is associated with the malicious requests? »

Filtre : `http.request && ip.src == <attacker>`. Ajouter la colonne `http.user_agent` ou
inspecter les headers d'une requête. Le User-Agent du bot est souvent distinctif (nom d'outil
de stress-test, chaîne générique ou fantaisiste).

Flag : `CTF{REDACTED}`

### BLACKHOLE 6 (15 pts) — « What is the duration of the attack, in seconds? »

Filtrer les requêtes de l'attaquant : `ip.src == <attacker>`. Prendre le timestamp du premier
et du dernier paquet. En tshark :

```bash
tshark -r CTF1.pcapng -Y "ip.src == <attacker>" -T fields -e frame.time_epoch | \
  awk 'NR==1{first=$1} END{printf "%.0f\n", $1-first}'
```

Flag : `CTF{REDACTED}`

### BLACKHOLE 7 (15 pts) — « How many HTTP requests does the capture contain? »

```bash
tshark -r CTF1.pcapng -Y "http.request" | wc -l
```

Attention : compter **toutes** les requêtes HTTP du pcap (pas seulement celles de l'attaquant),
sauf si la question précise « malicious requests ».

Flag : `CTF{REDACTED}`

### BLACKHOLE 8 (30 pts) — « What is the flag hidden in an HTTP header? »

Parcourir les headers HTTP inhabituels. Chercher un header custom contenant `CTF{` ou
`battleCTF{` :

```bash
tshark -r CTF1.pcapng -Y "http" -T fields -e http.request.full_uri -e http.response.code \
  -e http.file_data -e http.request.line | grep -iE 'ctf\{|flag'
```

Ou dans Wireshark : `Edit → Find Packet → String → "CTF{"` sur les bytes du paquet.

Flag : `CTF{REDACTED}`

## Leçons

- `Statistics → Conversations` dans Wireshark donne immédiatement la paire attaquant/cible.
- `tshark -T fields -e <champ>` permet d'extraire n'importe quelle valeur à grande échelle.
- Les headers HTTP custom sont un vecteur classique pour cacher des flags dans les pcap.
- Toujours vérifier si la question porte sur *tout* le trafic ou seulement celui de l'attaquant.

---

*Write-up par **k1lls3vr4q** — BUG|PWN CTF · Operation BLACKHOLE 1→8.*
