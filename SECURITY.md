# Security Policy

This repository holds the Rust node that runs the Inazuma network. Bugs here can affect real money, so please read this
before you open anything public.

## Never open a public issue for a vulnerability

If a bug could let someone steal funds, halt the chain, forge a block, drain a
faucet, or read a user's private key, report it privately.

**Email security@inazuma.network.** Include:

1. What the bug is, in one or two sentences.
2. Exact steps or a script that reproduces it.
3. What an attacker gains (funds, downtime, data).
4. Affected version, commit, or endpoint.
5. How you would like to be credited, if at all.

You do not need a proof-of-concept exploit. A clear description is enough.

## What happens next

| When | What we do |
| --- | --- |
| Within 48 hours | We confirm we received it and say who is handling it |
| Within 7 days | We confirm or reject the finding and give you a severity |
| Within 30 days | Fix shipped, or a written plan with dates if it needs a consensus change |
| After the fix | Public advisory, credit to you unless you prefer to stay anonymous |

Please give us those 30 days before publishing. If a fix needs an activation
height, the timeline follows the release, and we will tell you the target block.

## Severity, in plain terms

| Level | Meaning | Examples |
| --- | --- | --- |
| Critical | Funds can be stolen or created, or the chain stops | Signature bypass, double spend, mint bug, consensus halt |
| High | A validator or node can be broken remotely | Remote crash, memory exhaustion, state divergence |
| Medium | Denial of service with cost, or leaked secrets in logs | RPC flood bypass, key material in a log line |
| Low | Local-only or needs unrealistic conditions | Crash needing an already-root attacker |

## In scope

- Code in this repository, on the `main` branch.
- The public network endpoints it talks to.

## Out of scope

- Attacks that need a user to hand over their secret key or seed.
- Volume-based network floods without a protocol bug (send those as normal issues).
- Findings from automated scanners with no working impact.
- Third-party sites or forks we do not run.

## Operator hardening

If you run a node, faucet, or RPC endpoint, keep secrets out of shell history and
process arguments, bind admin RPC to localhost, keep the firewall closed except
for P2P and the ports you intend to serve, and back up keys offline. Details are
in the validator guide in [inazuma-docs](https://github.com/inazuma-network/inazuma-docs).
