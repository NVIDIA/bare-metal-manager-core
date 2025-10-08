# Managing Azure Accounts for Forge DB Backups

**There is a Teams recording [here](https://nvidia-my.sharepoint.com/:v:/p/chetn/EQMWieXMPVxAhwxs1EK5KGQBX3IaGvJeLWWTkaa4T6nSYA?nav=eyJyZWZlcnJhbEluZm8iOnsicmVmZXJyYWxBcHAiOiJPbmVEcml2ZUZvckJ1c2luZXNzIiwicmVmZXJyYWxBcHBQbGF0Zm9ybSI6IldlYiIsInJlZmVycmFsTW9kZSI6InZpZXciLCJyZWZlcnJhbFZpZXciOiJNeUZpbGVzTGlua0NvcHkifX0&e=GW3qmo) that walks through all of this.** In the recording, I mention I'll be sharing out links and a doc that also goes over it. This is that doc, and these are those links!

## Requesting Storage

First, and this has of course already been completed (since we have storage), but you first have to request an account through the [nvidia Security Portal](https://securityportal.nvidia.com). This is where you go to request Azure, AWS, or GCP subscriptions, give business justification, as well as an estimated monthly cost. It then goes through:
- VP Approval
- Finance Approval
- PSOC/Security Approval
- CloudSec Provisioning

In our case:
1. I requested a [new Azure subscription](https://securityportal.nvidia.com/cloudos-new-account/azure).
2. Was able to see the request in [My Requests](https://securityportal.nvidia.com/my-requests).
3. Was able to click the subscription request [here](https://securityportal.nvidia.com/cloudos-account-request/67db47b3c991b9069adfc9b2).

You may or may not be able to see the original subscription request, depending on access.

Now, when you request a new subscription, DL groups will be provisioned automatically based on the subscription name, with "admin" and "engineer" groups that map into the corresponding AWS/Azure/GCP roles. In our case, we have:
- [access-azure-forge-db-backups-admin](https://dlrequest/GroupID/Groups/Properties?identity=YzM1YTUzM2RhOTU1NGY4ZTkwYWE0YzEyOTIyYjg5ZmJ8Z3JvdXA=)
- [access-azure-forge-db-backups-engineer](https://dlrequest/GroupID/Groups/Properties?identity=MTBjNjViZWMzODhiNDhiODlkZGJmOTMyZjdlMDgyNDd8Z3JvdXA=)

Once approved, I was able to see the subscription (as well as anyone with access per the DL group), by:
1. Going back to the [nvidia Security Portal](https://securityportal.nvidia.com).
2. Clicking [Azure](https://securityportal.nvidia.com/cloudos-account-info/azure) at the top.
3. Seeing the [forge-db-backups](https://securityportal.nvidia.com/cloudos-account-info/azure/d0b9c5d4-d97a-491e-9e00-475af5599a2e) subscription.

## Logging in to Azure

To access the storage subscription, you simply login using your nvidia SSO credentials to https://portal.azure.com

This will be where you can:
- Work with the subscription to make new storage accounts.
- Work with the storage accounts.
- Etc.

Now, when you login, **you won't see the forge-db-backups subscription.** This is because Azure subscriptions created through Security Portal utilize **Microsoft Entra Privileged Identity Management (PIM)** for enabling "Just-In-Time" SSO access to Azure subscriptions. Please see [How to: Login to the Azure Subscription through SSO](https://confluence.nvidia.com/pages/viewpage.action?pageId=1890664130) for the "official" details, which is basically what this section explains.

### 1. Go Into PIM

You will need to "activate" your role (either "admin" or "engineer", which are backed by the aforementioned [access-azure-forge-db-backups-admin](https://dlrequest/GroupID/Groups/Properties?identity=YzM1YTUzM2RhOTU1NGY4ZTkwYWE0YzEyOTIyYjg5ZmJ8Z3JvdXA=) and [access-azure-forge-db-backups-engineer](https://dlrequest/GroupID/Groups/Properties?identity=MTBjNjViZWMzODhiNDhiODlkZGJmOTMyZjdlMDgyNDd8Z3JvdXA=) DL groups), which is how you will be able to actually see the subscription in the portal, and work with it (it's completely invisible until you do this).

To do so:
1. Click on the "**Microsoft Entra Privileged Identity Management**" button in the portal home screen.
2. Click on "**Manage -> Azure resources**".
3. Click on "**Activate role**" at the top of the view.
4. You will see "**NVIDIA Admin**" and/or "**NVIDIA Engineer**" roles for the **forge-db-backups** resource.
5. Click "**Activate**" on the one you wish to active.


Once activated, you can go BACK to the main Azure Portal, and you will be able to see the **forge-db-backups** subscription, and can now work with it, including:
- Clicking on the **forge-db-backups** subscription itself.
- Clicking on "**Storage Accounts**" and seeing all of the storage accounts within the subscription.
- Etc

## Storage Accounts

These are direct links to each storage account. The idea is that we have a storage account in each Azure region to be as closely colocated as each Forge Azure colo site as possible; we want backups to be both quick and hopefully available within a given region.

Each account name is specific to the region, and directly maps to a URL of `https://<account>.blob.core.windows.net`.

These are all within the [forge-db-backups-resource-group](https://portal.azure.com/?feature.msaljs=true#@NVIDIA.onmicrosoft.com/resource/subscriptions/d0b9c5d4-d97a-491e-9e00-475af5599a2e/resourceGroups/forge-db-backups-resource-group) resource group, within the [forge-db-backups](https://portal.azure.com/?feature.msaljs=true#@NVIDIA.onmicrosoft.com/resource/subscriptions/d0b9c5d4-d97a-491e-9e00-475af5599a2e) subscription.

Assuming you are logged in with your role activated, all of these links should work.

For example, if I wanted to list my `chet-testing` container in `forgedbuswest3`, I could use `azcopy` to do something like:

```
❯ azcopy list https://forgedbuswest3.blob.core.windows.net/chet-testing
hello-world.txt; Content Length: 10.00 B
```

The accounts are:
- [forgedbcanadacentral](https://portal.azure.com/?feature.msaljs=true#@NVIDIA.onmicrosoft.com/resource/subscriptions/d0b9c5d4-d97a-491e-9e00-475af5599a2e/resourceGroups/forge-db-backups-resource-group/providers/Microsoft.Storage/storageAccounts/forgedbcanadacentral) (Canada Central)
- [forgedbgermanywestcntral](https://portal.azure.com/?feature.msaljs=true#@NVIDIA.onmicrosoft.com/resource/subscriptions/d0b9c5d4-d97a-491e-9e00-475af5599a2e/resourceGroups/forge-db-backups-resource-group/providers/Microsoft.Storage/storageAccounts/forgedbgermanywestcntral) (Germany West Central)
- [forgedbjapaneast](https://portal.azure.com/?feature.msaljs=true#@NVIDIA.onmicrosoft.com/resource/subscriptions/d0b9c5d4-d97a-491e-9e00-475af5599a2e/resourceGroups/forge-db-backups-resource-group/providers/Microsoft.Storage/storageAccounts/forgedbjapaneast) (Japan East)
- [forgedbjapanwest](https://portal.azure.com/?feature.msaljs=true#@NVIDIA.onmicrosoft.com/resource/subscriptions/d0b9c5d4-d97a-491e-9e00-475af5599a2e/resourceGroups/forge-db-backups-resource-group/providers/Microsoft.Storage/storageAccounts/forgedbjapanwest) (Japan West)
- [forgedbswedencentral](https://portal.azure.com/?feature.msaljs=true#@NVIDIA.onmicrosoft.com/resource/subscriptions/d0b9c5d4-d97a-491e-9e00-475af5599a2e/resourceGroups/forge-db-backups-resource-group/providers/Microsoft.Storage/storageAccounts/forgedbswedencentral) (Sweden Central)
- [forgedbuseast](https://portal.azure.com/?feature.msaljs=true#@NVIDIA.onmicrosoft.com/resource/subscriptions/d0b9c5d4-d97a-491e-9e00-475af5599a2e/resourceGroups/forge-db-backups-resource-group/providers/Microsoft.Storage/storageAccounts/forgedbuseast) (East US)
- [forgedbuswest2](https://portal.azure.com/?feature.msaljs=true#@NVIDIA.onmicrosoft.com/resource/subscriptions/d0b9c5d4-d97a-491e-9e00-475af5599a2e/resourceGroups/forge-db-backups-resource-group/providers/Microsoft.Storage/storageAccounts/forgedbuswest2) (West US 2)
- [forgedbuswest3](https://portal.azure.com/?feature.msaljs=true#@NVIDIA.onmicrosoft.com/resource/subscriptions/d0b9c5d4-d97a-491e-9e00-475af5599a2e/resourceGroups/forge-db-backups-resource-group/providers/Microsoft.Storage/storageAccounts/forgedbuswest3) (West US 3)


## Storage API Access Keys

The `wal-g` component within `postgres-operator` uses an API access key to manage backups for a given site. The API access key can be created/updated via the "**Security + networking > Access keys**" section within a given storage account. For example:

1. Go to [forgedbuswest3](https://portal.azure.com/?feature.msaljs=true#@NVIDIA.onmicrosoft.com/resource/subscriptions/d0b9c5d4-d97a-491e-9e00-475af5599a2e/resourceGroups/forge-db-backups-resource-group/providers/Microsoft.Storage/storageAccounts/forgedbuswest3).
2. Click "**Security + networking > Access keys**".
3. You will see keys.

*Note that two keys exist, `key1` and `key2`, to allow you to be able to rotate keys.*

## Accessing storage with azcopy and az using Azure AD

In addition to the API access keys, you will probably want to leverage Azure AD credentials to use `azcopy` and `az` locally. To do this, you will need to get a few things from the app registration, including:
- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_CLIENT_SECRET`

To do this,
1. Go to [App Registrations](https://portal.azure.com/?feature.msaljs=true#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade), or just search for "app registrations" in the Azure Portal search box.
2. Click on the [forge-db-backups-azure](https://portal.azure.com/?feature.msaljs=true#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/eb7aae6a-2ccb-4613-a4d4-7502b7e30c96/isMSAApp~/false) application.

You will now see a few things on the overview page:
- "**Application (client) ID**" -- This is the value to use for your `AZURE_CLIENT_ID` environment variable.
- "**Directory (tenant) ID**" -- This is the value to use for your `AZURE_TENANT_ID` environment variable.

Now, to get an `AZURE_CLIENT_SECRET`:
1. Click "**Manage > Certificates & secrets**"
2. Click "**New client secret**"

You can now use this secret, along with your client + tenant ID values, to use `az` and `azcopy`. Note that `wal-g` does NOT use these values; it only supports the API access keys above.

*Note that secrets can only be viewed once when created; there's no way to view them again.*
