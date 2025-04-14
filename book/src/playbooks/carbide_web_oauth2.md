# Azure Set-up

For managing client secrets and redirect URIs, the steps found in the [azure oidc](azure_oidc.md) playbook can be applied to the [carbide-web app](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/5ae5fa35-be8e-44cc-be7b-01ff76af5315/isMSAApp~/false) registered in the Entra portal.


# Carbide Web

The oauth2 in carbide-web has defaults for most settings:

|ENV|DESCRIPTION|DEFAULT|
|----|----|----|
|CARBIDE_WEB_ALLOWED_ACCESS_GROUPS|The list of DL groups allowed to access carbide-web|"swngc-forge-admins,ngc-forge-sre,swngc-forge-dev"|
|CARBIDE_WEB_ALLOWED_ACCESS_GROUPS_ID_LIST|The list of UUIDs in Azure that correspond to the DL groups allowed to access carbide-web|"1f13d1bb-6d7e-4fa5-9abf-93e24e7b5a4e,80f709a0-77a7-4a15-899d-7abba0ffdc1f,d03b7e2a-673b-4088-9af0-545a2d2f4c5d"|
|CARBIDE_WEB_OAUTH2_CLIENT_ID|The app ID of carbide-web in Azure/Entra|5ae5fa35-be8e-44cc-be7b-01ff76af5315|
|CARBIDE_WEB_OAUTH2_TOKEN_ENDPOINT|  The URI for our tenant ID |"https://login.microsoftonline.com/43083d15-7273-40c1-b7db-39efd9ccc17a/oauth2/v2.0/token"|


**The following environment variables do not have defaults and must be set in the forged repo:**

|ENV|DESCRIPTION|
|----|----|
|CARBIDE_WEB_OAUTH2_CLIENT_SECRET|A secret used to talk to MS entra/graph.  This comes from the Azure step at the start of this playbook.  It's set in the forged repo at https://gitlab-master.nvidia.com/nvmetal/forged/-/tree/main/bases/carbide/api/secrets?ref_type=heads.|
|CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY|A secret used for encrypting the cookie values used for sessions.  Although there's no default, we set this to the site's postgres password in the [forged repo](https://gitlab-master.nvidia.com/nvmetal/forged/-/blob/main/bases/carbide/api/deployment.yaml).|
|CARBIDE_WEB_HOSTNAME|A hostname specific for each site that's needed for redirects.  The value must match what's set in the Azure/Entra portal for the [redirect URIs of the carbide-web app](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Authentication/appId/5ae5fa35-be8e-44cc-be7b-01ff76af5315/isMSAApp~/false).  We're currrently setting this via a configmap set in each site's kustomization.yaml in the forged repo.|


# Updating the Production Client Secret

In the forged repo, overwrite bases/carbide/api/secrets/azure-carbide-web-sso.enc.yaml with the following:

```
apiVersion: v1
kind: Secret
metadata:
    name: azure-sso-carbide-web-client-secret
type: Opaque
data:
    client_secret: <base64 encoded version of the client secret from Azure>
```

Then run
```
sops -e -i bases/carbide/api/secrets/azure-carbide-web-sso.enc.yaml
```
And then commit your changes.

If using ArgoCD to update the deployment, Argo will not see the secret as "changed" and you'll need to take the following steps:

- Uncheck `respect ignore differences`
- Select only the /Secret/forge-system/azure-sso-carbide-web-client-secret resource
- Sync
- Perform another sync as you normally would

If the _only_ thing you are changing is the secret, you might have to force a redeploy of the Carbide API service, or delete the existing pods so they get recreated and pick up the change in secret.



# Alternative Auth Flow

Some teams use gitlab automation to pull data from the Web UI.

To provide access using the alternative auth flow, perform the following steps:
- Create a new secret for the team/process: https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/5ae5fa35-be8e-44cc-be7b-01ff76af5315/isMSAApp~/false
- Securely provide the team the new secret.  https://privatebin.nvidia.com/ should be fine, but remember to select `Burn after reading` and a short expiration (1hr or less).

The automated process will then be able to fetch an encrypted cookie that will grant access for 10 minutes.

Example:

```
curl --cookie-jar /tmp/cjar --cookie /tmp/cjar --header 'client_secret: ...' 'https://<the_web_ui_address>/admin/auth-callback'
curl --cookie /tmp/cjar 'https://<the_web_ui_address>/admin/managed-host.json'
```





