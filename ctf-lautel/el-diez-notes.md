# El Diez — notes de résolution

- **Challenge :** El Diez
- **Catégorie :** web
- **Statut :** résolu, soumission laissée à l'utilisateur

## Chaîne validée

1. L'endpoint `/api/pases?anio=` est vulnérable à une injection SQL `UNION`, permettant d'extraire la valeur de configuration `redis_auth`.
2. `POST /api/pase/9/reenviar` avec `X-Canal: telegrama` déclenche le bot. Depuis le backend local, utiliser `Host: 127.0.0.1:8080` pour que le bot revisite l'application et mette en cache sa fiche CSS.
3. `/cuenta/ficha.css` expose le profil auditeur et son `mtoken`. La clé publique est disponible sous `/keys/jwt-public.pem`.
4. L'authentification accepte un JWT HS256 signé manuellement avec les octets PEM publics, `kid=eldiez26` et les claims `sub=auditor_interno`, `rol=raiz`, `escenario=postinicio`.
5. `POST /consola/operador/gate` permet le relais gopher interne avec `modalidad=relay`, `tramo=interno` et le `mtoken`.
6. Via RESP/gopher, authentifier Redis, écrire `gtr:listo=1`, puis `gtr:cmd=cat flag.txt`. Le worker publie le résultat consultable sur `/consola/operador/estado`.

## Validation distante

Rejouée depuis le serveur contre le backend local `127.0.0.1:18083`, avec l'en-tête `Host: 127.0.0.1:8080`. Les étapes SQLi, fuite cache, JWT, relais Redis et récupération de sortie ont toutes réussi. Aucun flag, cookie ou secret intermédiaire n'est conservé dans ce dépôt. Aucune soumission n'a été effectuée.

## Pièges observés

- Le sous-domaine correct est `eldiez.13.63.167.233.nip.io` (sans tiret); celui avec `el-diez` ne correspond pas à cette application.
- Le validateur de test fourni par l'organisateur charge les secrets locaux et compare le flag directement : ne pas l'utiliser pour une vérification indépendante.
- La route de rejeu du bot doit être déclenchée avant la lecture de la fiche mise en cache.
- Les écritures Redis d'armement et de commande sont deux actions distinctes; laisser ensuite le worker périodique traiter la commande.

## Référence réutilisable

Voir [JWT HS256 avec clé publique](../knowledge/web/jwt-confusion-cle-publique-hs256.md) et les notes SSRF/gopher de la skill `ctf-web`.
