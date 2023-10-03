# Azure OIDC and Forge

You must be a member of the Forge SRE or Forge DEV groups in Active Directory.  This document is intended for use by Forge SRE and DEV only.  If you are trying to set up a Forge site that Forge SRE does not manage,  you must modify ArgoCD to accommodate your setup.

Each Forge site needs to have a redirect URI added to the Azure OIDC and, in the case of ArgoCD, a site-specific secret.

There is a single shared secret in some cases, such as Grafana.  The likelihood of someone causing harm to a forge site through Grafana is low.  Argo is our deployment system; thus, the security controls are stricter

## Adding new client secrets

> **NOTE:** Login to azure.com using your Nvidia SSO credentials

<figure>
<img src=../static/playbooks/azure_oidc/azure_first.png width="1300" height=170
alt="Select App Registrations">
<figcaption>Select App Registrations</figcaption>
</figure>

<figure>
<img src=../static/playbooks/azure_oidc/azure_choose_app.png width="1200" height=530
alt="Choose application">
<figcaption>Choose which application you want to change</figcaption>
</figure>

<figure>
<img src=../static/playbooks/azure_oidc/azure_app_overview.png width="1100" height=780
alt="Click Certificate and Secrets">
<figcaption> Click Certificates & Secrets</figcaption>
</figure>

<figure>
<img src=../static/playbooks/azure_oidc/azure_app_select_new_secret.png width="900" height="425"
alt="Select new secret">
<figcaption>Click "New Secret"</figcaption></figure>
<figure>
<img src=../static/playbooks/azure_oidc/azure_app_secret_values.png width="800" height=425
alt="Fill in secret value">
<figcaption>Fill in secret details and click "Add" at the bottom</figcaption></figure>
</fiigure>

> **NOTE:** Make note of the "Value" that was generated. You cannot view the "Value" if you navigate away from the screen

## Adding redirect URLs to Azure OIDC  config

> **NOTE:** Login to azure.com using your Nvidia SSO credentials

<figure>
<img src=../static/playbooks/azure_oidc/azure_first.png width="1300" height=170
alt="Select App Registrations">
<figcaption>Select App Registrations</figcaption>
</figure>

<figure>
<img src=../static/playbooks/azure_oidc/azure_choose_app.png width="1200" height=530
alt="Choose application">
<figcaption>Choose which application you want to change</figcaption>
</figure>

<figure>
<img src=../static/playbooks/azure_oidc/azure_app_select_authentication.png width="1200" height=820
alt="Click Authentication">
<figcaption> Click Authentication</figcaption>
</figure>

<figure>
<img src=../static/playbooks/azure_oidc/azure_add_redirect_uri.png width="1200" height=670
alt="Add redirect URL">
<figcaption>Add redirect url</figcaption>
</figure>

## Adding the new secret in Forged repo

The ArgoCD SSO Kubernetes `secret`` is required during the bootstrapping of a new environment

1. In `envs/<env>/bootstrap/secerts` create new file `secret.enc.env`.
2. Inside `secret.enc.env` include the following:

```ini
url="https://<url of argocd>
oidc.azure.clientSecret="<secretGeneratedInAzure>"
```

3. Encrypt the file using sops: `sops -e -i secret.enc.env`
4. Create a file `envs/<env>/bootstrap/secret-generator.yaml`

```yaml
apiVersion: viaduct.ai/v1
kind: ksops
metadata:
  name: argocd-sso-generator
  annotations:
    config.kubernetes.io/function: |
        exec:
          path: ksops
secretFrom:
  - metadata:
      labels:
        app.kubernetes.io/part-of: argocd
      name: argocd-sso
      namespace: argocd
    envs:
      - ./secrets/secret.enc.env
```

5. Inside the `kustomization.yaml` file in the bootstrap directory, make sure it includes:

```yaml
...
generators:
  - secret-generator.yaml
```

6. Proceed with bootstrapping the new environment
