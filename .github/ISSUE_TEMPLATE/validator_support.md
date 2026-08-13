---
name: Validator support
about: Help running a node or joining the validator set
labels: validator
---

Read `docs/validator.md` first — the troubleshooting table covers genesis mismatches,
peer discovery, missed slots and jailing.

**Step you are stuck on**

**Output of**
```
inazuma status
curl -s localhost:9933 -d '{"jsonrpc":"2.0","id":1,"method":"inaz_nodeStatus"}'
curl -s localhost:9933 -d '{"jsonrpc":"2.0","id":1,"method":"inaz_netInfo"}'
```

**Hardware and network** (vCPU / RAM / disk type, open ports)

Never paste a private key or the contents of `validator.env`.
