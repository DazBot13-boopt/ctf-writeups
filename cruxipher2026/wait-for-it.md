# Wait For It (forensics, 50 pts) — RÉSOLU

- **Catégorie** : forensics / packet analysis
- **Fichier** : `files/capture.pcap`
- **Flag** : `cruXipher{REDACTED}` (contenu = "TIMING_IS_EVERYTHING" en MAJUSCULES, soumission acceptée)

## Observations

La capture (66 s) contient trois types de trafic :

- **DNS** : requêtes vers des domaines réels (github, google, spotify…) + 17 requêtes `crux.local`
  renvoyant chacune une IP `142.250.x.y` différente → fausse piste (DNS tunneling apparent).
- **HTTP** : 24 `GET /` renvoyant `<html>ok</html>` → bruit.
- **IRC** (serveur `10.13.37.7:6667`), deux clients :
  - `192.168.1.23` sur `#ctf` : pseudos `r00t`/`n3o`/`bot`, spam avec faux flag `cruXipher{n0t_th3_fl4g_lol}`.
  - `192.168.1.42` sur `#offtopic` : `eve` dit « the flag is in the timing », `mallory` poste
    `cruXipher{d3c0y_str34m}`, `eve` ajoute « just kidding... or am I ».

Tout le **contenu textuel** n'est que leurre. Le topic « keep your ears open » + l'indice
« the flag is in the timing » orientent vers le **rythme des paquets**.

## Résolution

Les messages IRC arrivent en **rafales** (paquets à 6–14 ms) séparées par des pauses de
~100 ms, ~300 ms ou >400 ms. Deux grandeurs encodent du Morse :

- **taille de rafale** : petite (~10–14 msg) = point, grande (~27–38 msg) = trait ;
- **durée de pause** : moyenne = séparation d'élément, longue = fin de lettre, très longue = répétition.

Décodage Morse (avec `..--.-` = `_`) :

- `#ctf` (192.168.1.23) → `TIMING_IS_EVERYTHING` (répété 2×) → **le flag**.
- `#offtopic` (192.168.1.42) → `NICE_TRY` (répété 3×) → encore un leurre.

Le Morse ne code pas la casse : la version minuscule a été refusée, la version
**MAJUSCULE** acceptée.

## Soumission

`POST /api/v1/challenges/attempt` (CTFd, `challenge_id=6`) → `{"status":"correct"}`.

## Piège principal

Faux flags dans le texte + indice « timing… just kidding » conçus pour envoyer le solveur
sur de mauvaises pistes (octets des IP DNS, RTT HTTP, TTL, binaire naïf des gaps). La vraie
donnée est le **Morse dans la durée des rafales**. Fiche générique :
`knowledge/forensics/pcap-timing-covert-channel-morse.md`.
