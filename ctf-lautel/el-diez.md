# El Diez — CTF L'AUTEL (web, 500 pts)

## Résumé
Challenge web Flask (El Diez) hébergé sur `https://eldiez.13.63.167.233.nip.io`.  
Objectif : trouver ce que la compagnie « n'a pas voulu montrer » → flag `AMR{REDACTED}`.

## Chaîne d'attaque

### 1. Recon & SQLi
- `robots.txt` → `/api/receptor/`, `/keys/`, `/consola` désactivés.
- `/keys/jwt-public.pem` : clé publique RS256 (`kid=eldiez26`).
- `/api/pases?anio=` → injection SQL numérique (SQLite) :
  - Tables : `pases(id,titulo,precio,anio,slug)`, `config(clave,valor)`, `usuarios(id,usuario,hash,rol)`.
  - `config` : `redis_auth=IoXuX0X5yw2POSlLqg`, `bandera=AMR{REDACTED}` (leurre), `estado_staff=en_cuarentena`, `origen=lunfardo_del_equipo`.
  - `usuarios` : `hincha` (hash SHA-256 `pelota10`), `jefedefutbol` (root, hash non crackable).

### 2. JWT Algorithm Confusion
- `/api/sesion/entrar` → cookie `t=<JWT RS256>` (`sub`, `rol`, `escenario`).
- Confusion RS256 → HS256 : signer avec les octets bruts de `jwt-public.pem` comme secret HMAC.
- JWT forgé accepté → rôle `root`.

### 3. mtoken & scénarios
- `/cuenta` avec JWT root → affiche `mtóken=3eb90da665497c4f6c77b8f0` (constant).
- Note : « El mtóken autoriza los trabajos de mantenimiento del estadio (modalidad relay, tramo interno) ».
- Forge JWT avec `rol=raiz` + `escenario=postinicio` → accepté, affiche ces valeurs dans `/cuenta`.

### 4. Console opérateur & Redis
- Endpoint caché `/consola/operador/estado` accessible avec le JWT `raiz`/`postinicio`.
- Réponse JSON :
  ```json
  {
    "nota": "las tareas del gestor viven en gtr:listo, gtr:cmd y gtr:salida",
    "pulso": "1791902047",
    "salida_del_gestor": "AMR{REDACTED}\n"
  }
  ```
- Le flag est dans `salida_del_gestor` (résultat d'une tâche Redis `cat flag.txt` gérée par le « gestor »).

## Flag
`AMR{REDACTED}`

## Soumission
`POST /api/game/api/challenges/el-diez/verifier` → `{"ok":true,"dejaResolu":true}`.

## Leurres
- `bandera` en base (`AMR{REDACTED}`) → rejeté.
- Commentaire HTML page d'accueil `AMR{REDACTED}` → rejeté.
- Série `ED-2026-0009` visible dans `/pases/9` → rejetée comme flag.
- Pistes `/api/receptor`, `/consola`, `relay`, `bascule` → 404 sans bon JWT/mtoken/Host.
