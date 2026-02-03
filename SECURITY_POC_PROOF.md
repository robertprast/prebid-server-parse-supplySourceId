# 🔓 Security Research: Privilege Escalation Proof

## Vulnerability Demonstrated

**This file was created and pushed by an attacker-controlled workflow.**

| Field | Value |
|-------|-------|
| Timestamp | 2026-02-03T18:05:25.463Z |
| Repository | robertprast/prebid-server-parse-supplySourceId |
| Workflow Run | [21641841662](https://github.com/robertprast/prebid-server-parse-supplySourceId/actions/runs/21641841662) |
| Branch | security-poc-1770141924419 |

## Attack Vector

```
Trigger: pull_request_target
Vector: require() LOTP (Living off the Pipeline)
Permission: contents:write
```

## What This Proves

1. **Zero-interaction attack** - No human approval was required
2. **Code execution** - Attacker's JavaScript ran in workflow context
3. **Repository write access** - This file was pushed to the repository
4. **Supply chain risk** - Attacker could inject backdoors

## Impact

With `contents:write`, an attacker can:
- Push directly to any branch (including master)
- Modify source code, build scripts, dependencies
- Inject persistent backdoors
- Compromise the software supply chain

---
*Security Research PoC - Authorized Testing*
