---
name: ctf-welcome-to-demo4
description: Web app with a client-disabled 'is_admin' field leading to privilege escalation and potential flag exposure.
---

# Challenge: welcome to demo4

## Context
- Category: web
- Difficulty: medium
- Vuln Type: Privilege Escalation
- Hint: 提示提到了一个管理员密码哈希值，暗示可能存在密码管理或认证绕过问题。

## Attack Chain
1. Identify the web application's login functionality and default credentials.
2. Authenticate using the provided demo credentials.
3. Inspect the authenticated user interface for fields that can be manipulated.
4. Exploit the client-disabled 'is_admin' field by forcing a POST request to change the user's admin status.
5. Verify the privilege escalation by checking for new admin-only content or flags.

## Key Payloads
```
POST /system_config/1
name=demo&is_admin=1
```
