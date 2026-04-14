---
name: ctf-welcome-to-demo3
description: Web app with GraphQL IDOR allowing client-controlled userId to access other user's data
---

# Challenge: welcome to demo3

## Context
- Category: web
- Difficulty: medium
- Vuln Type: Insecure Direct Object References (IDOR)
- Hint: 查看你的医疗信息，尝试是否能找到其他人的医疗信息？？

## Attack Chain
1. Fingerprinted the app to identify it as a Flask/Werkzeug application branded `MedGuard`.
2. Authenticated with a low-privilege account using credentials `user:user`.
3. Inspected how medical data is fetched and identified client-controlled `userId` in GraphQL requests.
4. Confirmed the GraphQL schema exposed a hidden `flag` field through introspection.
5. Exploited IDOR/BOLA on GraphQL by querying `getPrescriptions(userId: 1)` as the authenticated user to access admin records.

## Key Payloads
```
query {
  getPrescriptions(userId: 1) {
    id
    userId
    prescriptionDetails
    flag
  }
}
```
