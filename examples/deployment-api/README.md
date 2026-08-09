# Deployment API (HTTP authorization)

This stateless HTTP service asks auth-master on every request. It never follows
redirects containing a token and never caches authorization results.

## Role model

- `deploy.global-admin` can deploy and delete every application.
- `deploy.developer` can deploy every application, but cannot delete one.
- `deploy.app.<slug>.admin` can deploy and delete only that application.

Start the isolated stack from the repository root:

```sh
make -C examples up EXAMPLE=deployment-api
```

The command creates the complete role matrix through auth-master's public APIs
and prints the seeded personas. The UI is at `http://127.0.0.1:8192`, auth-master
at `http://127.0.0.1:8292`, and Mailpit at `http://127.0.0.1:8392`.

All personas use `Example!Passw0rd9`. Print a fresh token and paste it into the
UI:

```sh
make -C examples token EXAMPLE=deployment-api PERSONA=developer
```

Persona keys are `global`, `developer`, `billing`, and `stranger`. Try both
`billing` and `other`. The UI reports authorization decisions only; it does not
perform or persist a real deployment.

Deploy or delete with a human access token:

```sh
curl -i -X POST -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:8192/apps/billing/deploy
curl -i -X DELETE -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:8192/apps/billing
```

Application slugs are lowercase letters, digits, and hyphens, up to 63 bytes.
The bearer token is sent in the JSON body expected by auth-master; the subject
is derived only from the verified token.

`make -C examples seed EXAMPLE=deployment-api` repairs missing roles and
memberships without duplication. `reset EXAMPLE=deployment-api` discards and
recreates the local stack. Test targets tear their stacks down when finished.
