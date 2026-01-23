# Azure Set-up

For managing client secrets and redirect URIs registered in the Entra portal.

# Carbide Web

The oauth2 in carbide-web has defaults for most settings:

|ENV|DESCRIPTION|
|----|----|
|CARBIDE_WEB_ALLOWED_ACCESS_GROUPS|The list of DL groups allowed to access carbide-web|
|CARBIDE_WEB_ALLOWED_ACCESS_GROUPS_ID_LIST|The list of UUIDs in Azure that correspond to the DL groups allowed to access carbide-web|
|CARBIDE_WEB_OAUTH2_CLIENT_ID|The app ID of carbide-web in Azure/Entra|
|CARBIDE_WEB_OAUTH2_TOKEN_ENDPOINT|  The URI for our tenant ID |
|CARBIDE_WEB_OAUTH2_CLIENT_SECRET|A secret used to talk to MS entra/graph.|
|CARBIDE_WEB_PRIVATE_COOKIEJAR_KEY|A secret used for encrypting the cookie values used for sessions.|
|CARBIDE_WEB_HOSTNAME|A hostname specific for each site that's needed for redirects.  The value must match what's set in the Azure/Entra portal for the URL of the carbide-api web interface|

# Alternative Auth Flow

Some teams use gitlab automation to pull data from the Web UI.

To provide access using the alternative auth flow, perform the following steps:
- Create a new secret for the team/process
- Securely provide the team the new secret

The automated process will then be able to fetch an encrypted cookie that will grant access for 10 minutes.

Example:

```
curl --cookie-jar /tmp/cjar --cookie /tmp/cjar --header 'client_secret: ...' 'https://<the_web_ui_address>/admin/auth-callback'
curl --cookie /tmp/cjar 'https://<the_web_ui_address>/admin/managed-host.json'
```
