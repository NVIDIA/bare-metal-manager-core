# Tenant Management with Keycloak

Keycloak-side administration for onboarding a Tenant: creating the realm roles that
NICo reads as org membership, creating the Tenant's identity, and granting the
privileged Tenant capability.

[Tenant Management](tenant_management.md) covers the NICo side of the Day 1 workflow
with `nicocli`, and states that meeting its role and membership conditions is an
identity-provider task. This page is that task, for deployments running Keycloak.

NICo never writes to Keycloak. It reads role claims out of each request's token and
derives org membership from them, so every step below is performed against Keycloak
directly and none of it has a NICo API equivalent.

## Before You Start

You should already have:

- A NICo deployment with `keycloak.enabled: true`, which is the default for
  `helm-prereqs/setup.sh` installs.
- Keycloak realm administrator credentials. The bundled dev instance uses
  `admin` / `admin`.
- The `PROVIDER_ADMIN` role in your own org, for the NICo-side steps.

Confirm the deployment is in Keycloak mode and read the values you will need:

```bash
kubectl -n nico-rest get configmap nico-rest-api-config \
  -o jsonpath='{.data.config\.yaml}' | grep -A 8 '^keycloak:'
```

A `setup.sh` install reports:

```yaml
keycloak:
  baseURL: http://keycloak.nico-rest:8082
  clientID: nico-rest
  clientSecretPath: /var/secrets/keycloak/client-secret
  enabled: true
  externalBaseURL: http://keycloak.nico-rest:8082
  realm: nico
  serviceAccount: true
```

Three of these govern the rest of this page.

`realm` is the only realm NICo reads. A single `nico-rest-api` release accepts tokens
from exactly one realm, so the Provider org and every Tenant org are realm roles inside
`nico`. There is no list-valued realm setting.

`externalBaseURL` is the issuer prefix NICo validates against the token's `iss` claim.
When it is an in-cluster address, as it is above, **tokens must be requested from inside
the cluster**. A token fetched through a port-forward to `localhost` carries a
non-matching `iss` and is rejected with `401`.

`serviceAccount: true` permits `client_credentials` tokens. Leave it enabled if the
Tenant will authenticate as a service account rather than as a user.

If `keycloak.enabled` is `false`, your deployment uses the `issuers` block instead and
this page does not apply. Onboarding a Tenant is then a configuration change rather than
realm administration, and the recipe is the "Provider with Multiple Tenant IdPs" example in
[Authentication and Authorization](https://docs.nvidia.com/infra-controller/rest-api-reference/authentication-and-authorization).

That page is also the authoritative field reference for the `keycloak` block itself, so use
it when you need the meaning of a setting rather than the procedure for using it.

## How NICo Derives Orgs and Roles

NICo reads the `realm_access.roles` claim and splits each realm role on a colon. The
part before the colon is the org name and the part after it is the role:

```text
acme-corp:TENANT_ADMIN     ->  org "acme-corp", role TENANT_ADMIN
acme-infra:PROVIDER_ADMIN  ->  org "acme-infra", role PROVIDER_ADMIN
```

Five properties of this mapping matter when you create roles.

- **Exactly one colon.** A role with none or with two is discarded without an error,
  which is why realm roles such as `admin` and `user` have no effect in NICo.
- **Org names are lowercased.** Use a lowercase org name, and use the same value in the
  `{org}` path segment of every request and in `api.org` in `~/.nico/config.yaml`.
- **Both role spellings are accepted.** `TENANT_ADMIN` and the legacy prefixed forms
  `NICO_TENANT_ADMIN` and `FORGE_TENANT_ADMIN` all match. The bundled realm uses the
  prefixed form. Use the unprefixed form for new roles.
- **Groups work indirectly.** Roles inherited from a Keycloak group are present in
  `realm_access.roles`, so assigning the realm role to a group and adding users to that
  group is equivalent to assigning it to each user.
- **Role changes are cached for up to one minute.** NICo stores the derived org data on
  the user record and refreshes it when it is older than that, so a role added in
  Keycloak takes effect on a request made after the cache expires.

The three roles and what each grants are listed in
[Organization & Permissions](org-permissions.md). A Tenant needs `TENANT_ADMIN` in its
own org. A Provider needs `PROVIDER_ADMIN` in the Provider org, because inviting a
Tenant, creating Allocations, and granting capabilities are all Provider-side
operations.

Human users additionally need an `oidc_id` user attribute, which is the key NICo uses to
locate or create the user record. The bundled `nico-rest` client already publishes it
through an `oidc-usermodel-attribute-mapper`, so no mapper work is required, but the
attribute has to be set on each user. Service accounts do not need it, because NICo uses
the token's `sub` claim when a `client_id` claim is present.

## Opening an Admin Session

The Keycloak Admin CLI ships inside the container image. Confirm it is present:

```bash
kubectl -n nico-rest exec deployment/keycloak -- \
  bash -c 'test -x /opt/keycloak/bin/kcadm.sh && echo FOUND || echo MISSING'
```

Open a shell and authenticate against the container's local listener on port `8080`:

```bash
kubectl -n nico-rest exec -it deployment/keycloak -- bash

/opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 --realm master \
  --user admin --password admin
```

The admin console is an alternative for operators who prefer a UI. The bundled instance
publishes no ingress, so reach it with
`kubectl -n nico-rest port-forward svc/keycloak 8082:8082` and open
`http://localhost:8082`. Using the console for administration is fine; the in-cluster
restriction described above applies only to token requests.

## Onboarding a Tenant Org

The examples use org `acme-corp` for the Tenant and realm `nico`.

### Create the Tenant's realm role

```bash
/opt/keycloak/bin/kcadm.sh create roles -r nico \
  -s name=acme-corp:TENANT_ADMIN \
  -s 'description=NICo Tenant Administrator for acme-corp'
```

### Create the Tenant's identity

Choose one of the two options below.

**Option A, a service-account client.** Suited to automation, and the pattern the
bundled `ncx-service` client uses. Requires `serviceAccount: true` in the NICo config.

```bash
/opt/keycloak/bin/kcadm.sh create clients -r nico \
  -s clientId=acme-corp-service \
  -s enabled=true \
  -s publicClient=false \
  -s serviceAccountsEnabled=true \
  -s standardFlowEnabled=false \
  -s directAccessGrantsEnabled=false \
  -s secret=REPLACE_WITH_A_GENERATED_SECRET

/opt/keycloak/bin/kcadm.sh add-roles -r nico \
  --uusername service-account-acme-corp-service \
  --rolename acme-corp:TENANT_ADMIN
```

**Option B, a human user.** The bundled realm ships no human users, so create one, set
`oidc_id`, and assign the role.

```bash
/opt/keycloak/bin/kcadm.sh create users -r nico \
  -s username=tenant-admin@acme-corp.example \
  -s email=tenant-admin@acme-corp.example \
  -s emailVerified=true \
  -s enabled=true \
  -s 'attributes.oidc_id=["acme-corp-admin-001"]'

/opt/keycloak/bin/kcadm.sh set-password -r nico \
  --username tenant-admin@acme-corp.example --new-password 'REPLACE_ME'

/opt/keycloak/bin/kcadm.sh add-roles -r nico \
  --uusername tenant-admin@acme-corp.example \
  --rolename acme-corp:TENANT_ADMIN
```

Any value for `oidc_id` works as long as it is unique within the realm and stable for
the life of the user. Changing it later makes NICo treat the login as a new user.

The doubled `u` in `--uusername` is not a typo. `kcadm.sh add-roles` prefixes each
option with the target type, so `--uusername` names a user and `--cclientid` names a
client, while `set-password` in the previous command takes a plain `--username`.

Exit the pod shell when finished.

### How a human user signs in

There is no browser step. `nicocli` implements the OAuth password grant, the client
credentials grant, and refresh-token renewal, and has no authorization-code or device-code
flow, so Keycloak's login page is never shown. `nicocli login` collects the username and
password (prompting when they are not supplied) and exchanges them at the realm's token
endpoint directly. This requires `directAccessGrantsEnabled` on the client, which the
bundled `nico-rest` client has.

Two `nicocli` flag defaults do not match a `setup.sh` deployment and have to be overridden:
`--keycloak-realm` defaults to `nico-dev` and `--client-id` defaults to `nico-api`, both of
which are Kustomize dev values.

`--keycloak-url`, `--keycloak-realm`, and `--client-id` are global flags, so they go before
`login`. Only `--client-secret`, `--username`, and `--password` belong to the subcommand.
Putting a global flag after `login` fails with `flag provided but not defined`.

```bash
nicocli \
  --keycloak-url http://keycloak.nico-rest:8082 \
  --keycloak-realm nico \
  --client-id nico-rest \
  login \
  --client-secret nico-local-secret \
  --username tenant-admin@acme-corp.example
```

`--keycloak-url` has to be the host in `externalBaseURL`, because that is what the issuer
is validated against. With the in-cluster default that name does not resolve from a
workstation, so interactive sign-in from outside the cluster needs one of:

- Set `externalBaseURL` to an externally resolvable hostname and expose Keycloak through an
  ingress, restricted to the endpoints listed in
  [Authentication and Authorization](https://docs.nvidia.com/infra-controller/rest-api-reference/authentication-and-authorization).
  This is the production answer.
- Or, for evaluation only, port-forward Keycloak and map the in-cluster name to `127.0.0.1`
  in `/etc/hosts`, so the issuer in the minted token still matches.

The Keycloak admin console is for realm administration, not for Tenant sign-in. Human
Tenants never need an account in it.

### Verify the token maps to the org

Request a token from inside the cluster. For Option A:

```bash
TENANT_TOKEN=$(kubectl run -i --rm --restart=Never \
  --image=curlimages/curl "curl-tenant-$$" -n nico-rest --quiet -- \
  -sf -X POST \
  "http://keycloak.nico-rest:8082/realms/nico/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=acme-corp-service&client_secret=REPLACE_WITH_A_GENERATED_SECRET" \
  2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
```

`helm-prereqs/keycloak/get-token.sh` does the same thing for the bundled `ncx-service`
client and is a working reference for the pattern.

Then confirm NICo resolves the identity, using a port-forward for the API call:

```bash
kubectl -n nico-rest port-forward svc/nico-rest-api 8388:8388 &

curl -sS "http://localhost:8388/v2/org/acme-corp/nico/user/current" \
  -H "Authorization: Bearer $TENANT_TOKEN"
```

A `200` response means the issuer validated, a realm role parsed into org
`acme-corp`, and the user record exists. Decode the token payload if it does not, then
check that `realm_access.roles` contains `acme-corp:TENANT_ADMIN`:

```bash
echo "$TENANT_TOKEN" | cut -d. -f2 \
  | awk '{l=length($0)%4; if(l) $0=$0 substr("====",1,4-l)}1' \
  | base64 --decode | python3 -m json.tool
```

## Completing the Setup in NICo

With the realm role in place, the remaining steps are the standard flow in
[Tenant Management](tenant_management.md). Two points are specific to this path.

**The Tenant must call `nicocli tenant current` before accepting an invitation.** That
call creates the Tenant record and links any invitation matching the org name. Until it
runs, reading the Tenant Account returns `403` and accepting it returns
`404 Org does not have tenant`, because the account's `tenantId` is still empty.

**A Tenant should not call `nicocli service-account current`.** In a deployment with
`serviceAccount: true`, that endpoint creates an Infrastructure Provider, a Tenant, and
an already-accepted Tenant Account for the calling org, which makes the org its own
Provider instead of a Tenant of yours. It is the bootstrap path for the Provider org, not
for an invited Tenant.

The order is:

1. Provider Admin creates the invitation. See
   [Creating the Link](tenant_management.md#creating-the-link).
2. Tenant Admin runs `nicocli tenant current` to create the Tenant and link the
   invitation.
3. Tenant Admin accepts, moving the account to `Ready`. See
   [Accepting the Invitation](tenant_management.md#accepting-the-invitation-tenant-side).
4. Provider Admin creates one Allocation per Site, which is what gives the Tenant
   capacity. See [Assigning Resources with Allocations](tenant_management.md#assigning-resources-with-allocations).

## Granting the Privileged Tenant Capability

Nothing about `targetedInstanceCreation` is Keycloak-specific. It is not a realm role and
it has no claim: a Provider Admin grants it on the Tenant Account after the Tenant
accepts, using `siteCapabilities`.

```bash
nicocli tenant-account update \
  --data '{"siteCapabilities":[{"siteIds":[],"targetedInstanceCreation":true}]}' \
  <account-id>
```

See [Granting Targeted Instance Creation](tenant_management.md#granting-targeted-instance-creation)
for the payload rules, the per-Site override behavior, how the effective value resolves,
plus how to read the current value.

The distinction worth keeping straight on this page is that Keycloak decides **who the
caller is and which org they act in**, while the Tenant Account decides **what that org is
allowed to do**. A realm role of `acme-corp:TENANT_ADMIN` makes someone a Tenant Admin for
`acme-corp`; it does not make them privileged. Adding a role such as
`acme-corp:PROVIDER_ADMIN` does not grant the capability either, it makes the org its own
Provider.

## Making Realm Changes Permanent

Changes made with `kcadm.sh` or the admin console live in Keycloak's database. They
survive pod restarts, but they are not represented in your configuration, so a rebuilt
realm loses them.

The bundled Keycloak imports `helm-prereqs/keycloak/realm-configmap.yaml` with
`--import-realm`, which imports only a realm that does not already exist. **Editing that
file and re-running `setup.sh` does not change an existing realm.** To fold a Tenant org
into the reproducible baseline, add its roles and identities to the file and re-import
from a clean state:

```bash
helm-prereqs/keycloak/clean.sh
helm-prereqs/keycloak/setup.sh
```

`clean.sh` drops the `keycloak` database and also deletes the `keycloak-client-secret`
Secret, which the `nico-rest-common` sub-chart owns. Re-run the `nico-rest` Helm upgrade
to restore it, then restart the API so it re-reads the signing keys from the rebuilt
realm:

```bash
kubectl -n nico-rest rollout restart deployment/nico-rest-api
```

Restarting the API while Keycloak is unavailable leaves it running with Keycloak
authentication inactive, so confirm Keycloak is ready first.

## Troubleshooting

| Symptom | Cause | Resolution |
|---------|-------|-----------|
| `401 Invalid authorization token in request` | Token `iss` does not match `externalBaseURL` plus the realm. Usually a token fetched over a port-forward | Request the token from inside the cluster |
| `401 Service accounts are not enabled` | Token carries a `client_id` claim but `keycloak.serviceAccount` is `false` | Enable `serviceAccount` in the values and upgrade, or use a user token |
| `403 User does not have any roles assigned` | No realm role parsed into an org. Usually a role name without exactly one colon | Check `realm_access.roles` in the decoded token |
| `403 Requested organization not found in token claims` | The `{org}` path segment does not match any role prefix. Often a case mismatch | Use the lowercase org name in the path and in `api.org` |
| `403 User does not have Tenant Admin role with org` | Role parsed, but it is not `TENANT_ADMIN` | Assign `acme-corp:TENANT_ADMIN` and retry after the one-minute cache expires |
| `404 Org does not have tenant` when accepting | `nicocli tenant current` has not been run for the Tenant org | Run it, then accept |
| `400 Tenant Account status is not Invited` | The account is already `Ready` | No action needed, the invitation was already accepted |
| A role added in Keycloak has no effect | Org data cached on the user record | Retry after one minute |
| Realm edits to `realm-configmap.yaml` do not appear | `--import-realm` skips an existing realm | Apply with `kcadm.sh`, or re-import from clean |

## Related Documentation

- [Tenant Management](tenant_management.md), the NICo-side Day 1 workflow with `nicocli`
- [Authentication and Authorization](https://docs.nvidia.com/infra-controller/rest-api-reference/authentication-and-authorization),
  the Day 0 auth configuration reference for both the `keycloak` and `issuers` modes
- [Organization & Permissions](org-permissions.md), the role model and what each role grants
- [Quick Start Guide](../getting-started/quick-start.md), deployment and token acquisition
  for the bundled realm
- [Reference Installation](../getting-started/installation-options/reference-install.md),
  deployment-side authentication wiring including the `issuers` alternative
