---
name: ctf-welcome-to-demo2
description: Web app with a SQL injection vulnerability protected by a keyword whitelist
---

# Challenge: welcome to demo2

## Context
- Category: web
- Difficulty: easy
- Vuln Type: SQL Injection
- Hint: 包含了sql注入的防护机制，但是好像有一个活多个单词白名单

## Attack Chain
1. Identify the `/jobs` endpoint and the `job_type` parameter.
2. Test for SQL injection by sending a single quote character `{"job_type":"'"}`.
3. Observe the server error response indicating SQL injection vulnerability.
4. Bypass the whitelist protection by using a comment-based payload `{"job_type":"private'--"}`.

## Key Payloads
```
{"job_type":"'"}
```
```
{"job_type":"private'--"}
```
