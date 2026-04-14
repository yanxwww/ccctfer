---
name: poc
description: 根据挑战名称或关键词查找并输出对应的CTF/渗透测试POC详情，包含攻击链、关键Payload和利用步骤。用法：/poc layer-breach
allowed-tools: Read
---

# CTF / 渗透测试 POC 技能

## 用法

```
/poc <挑战名称或关键词>
```

支持按挑战名称、漏洞类型或关键词模糊匹配，例如：
- `/poc layer-breach`
- `/poc ssrf`
- `/poc upload`
- `/poc link`

## 执行步骤

1. **标准化输入**：将用户输入转为小写，用连字符替换空格
2. **查找索引**：在下方「POC索引」中找到最佳匹配项，获取文件路径
3. **读取文件**：用 Read 工具读取该路径的 SKILL.md（路径相对于本 SKILL.md 所在目录，即 `~/.claude/skills/poc/`）
4. **输出内容**：结构化输出以下内容：
   - 挑战名称 / 类别 / 难度 / 漏洞类型
   - 提示信息（Hint）
   - 攻击链（逐步说明）
   - 关键 Payload（可直接使用的命令/请求）

**模糊匹配规则**：
- 输入包含索引中任意一个关键词即视为匹配
- 多个匹配时，列出所有匹配项让用户选择
- 无匹配时，告知用户并列出库中所有可用 POC

---

## POC索引（共6条）

格式：`挑战名称 | 关键词 | 漏洞类型 | 文件路径`

- ctf-layer-breach | layer breach ssrf lfi file proxy | SSRF, Local File Inclusion | ctf-layer-breach/SKILL.md
- ctf-link-violation | link violation upload shell pivot internal | Upload Vulnerability, Internal Network Penetration | ctf-link-violation/SKILL.md
- ctf-welcome-to-demo1 | demo1 welcome privilege escalation admin is_admin profile | Privilege Escalation | ctf-welcome-to-demo1/SKILL.md
- ctf-welcome-to-demo2 | demo2 welcome sql injection whitelist job_type | SQL Injection | ctf-welcome-to-demo2/SKILL.md
- ctf-welcome-to-demo3 | demo3 welcome idor bola graphql medguard prescription | IDOR, GraphQL | ctf-welcome-to-demo3/SKILL.md
- ctf-welcome-to-demo4 | demo4 welcome privilege escalation admin hash password | Privilege Escalation | ctf-welcome-to-demo4/SKILL.md
