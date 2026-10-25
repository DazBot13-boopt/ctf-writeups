# cruXipher 2026 — Internal Affairs (web, 428 pts)

## Contexte

Portail RH « Crooxus Dynamics » exposé sur `https://internal-affairs.cruxipher.crux-bphc.com`.
Un seul endpoint applicatif : `POST /graphql`. Le front React n'envoie aucune credential :
le serveur choisit un utilisateur par défaut (`nora.bennett`, MANAGER).

Objectif : expliquer la faillite de février, c'est-à-dire lire l'événement d'audit
`AUD-2431` dont les champs détaillés sont réservés aux administrateurs.

## Reconnaissance

Introspection ouverte (`__schema`). Requêtes racine :

- `users(filter, limit, offset)`, `me`, `departments`, `serviceAccounts`
- `compensations` (admin), `compensationTrend`, `auditEvents(limit)`

Anomalie métier : `compensationTrend.averageSalary` passe de ~111 312 à ~765 919 le
2026-02-18, avec `markedAdjustment: true`. L'événement correspondant est `AUD-2431`
(`COMPENSATION_UPDATED`, 2026-02-18T16:42:09Z) mais `comment`, `previousSalary`,
`newSalary`, `actor` et `targetUser` renvoient « Administrator access required ».

Deux niveaux de refus distincts :

- « Not authorized to access this field » : `email`, `apiKey`, `secretToken`,
  `compensation` d'un autre utilisateur ;
- « Administrator access required » : détails des événements d'audit et `compensations`.

## Vulnérabilité

Le contrôle d'accès protège la **sortie** des champs sensibles, mais le même champ reste
utilisable dans le **filtre** `UserFilter` via `StringFilter` (`equals`, `startsWith`,
`endsWith`, `contains`). `apiKey` devient donc un oracle booléen.

Extraction caractère par caractère :

```graphql
{ users(filter:{username:{equals:"viktor.sloane"}, apiKey:{startsWith:"crooxus_live_"}}) { id } }
```

Un alphabet ASCII imprimable suffit. Confirmation par `endsWith` puis `equals` sur la valeur
complète. Clé obtenue pour `viktor.sloane` (CD-1001, ADMIN) : `<API_KEY>`.

Piège rencontré : le champ `me` reste câblé sur `nora.bennett` **même avec** le header
`x-api-key` valide. Tester `me` seul donne un faux négatif. En revanche, les champs
privilégiés changent immédiatement d'autorisation :

```bash
curl -s https://<HOST>/graphql \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: <API_KEY>' \
  -d '{"query":"{ auditEvents(limit:60){ id comment previousSalary newSalary actor{username} targetUser{username} } }"}'
```

Aliases, fragments et `@include/@skip` ne contournent pas le contrôle par résolveur ; le
bypass passe uniquement par l'oracle de filtre puis la réutilisation de la clé.

## Résultat

`AUD-2431` révèle le vrai coupable :

- acteur et cible : `theo.james` (CD-1127, ADMIN) ;
- salaire précédent : 105 125 → nouveau salaire : 42 000 000 ;
- commentaire : `FLAG{REDACTED}`.

Flag soumis via `POST /api/v1/challenges/attempt` (header `CSRF-Token`) : accepté.

## Leçons

- Un champ « interdit en lecture » mais filtrable est une fuite complète.
- Toujours tester un champ réellement privilégié avant de conclure qu'une clé est invalide.
- Vérifier les valeurs extraites avec `endsWith`/`equals` pour éviter les préfixes tronqués.
