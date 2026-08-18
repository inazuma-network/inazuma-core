# Security policy

## Reporting a vulnerability

Do **not** open a public issue for anything that could be used to steal funds, halt the
chain, or forge state. Report it privately through GitHub Security Advisories on this
repository ("Report a vulnerability").

Please include: affected component, chain height or commit, reproduction steps, and
impact. We aim to acknowledge within 72 hours and to ship a fix or a mitigation plan
before any public disclosure.

## In scope

Consensus safety and liveness, signature verification and key derivation, state root
correctness, slashing evidence handling, P2P handshake and framing, mempool admission,
RPC authentication and rate limiting, WASM contract sandboxing.

## Out of scope

Third-party RPC providers, wallets we do not ship, denial of service that requires
majority stake, and reports produced by scanners without a working reproduction.

## Hardening log

Fixes shipped from internal review and the conformance suite. Each is covered by
a regression test in `src/conformance.rs`, `src/battletest.rs` or `src/fuzz.rs`.

| Finding | Impact | Resolution |
| --- | --- | --- |
| Unchecked `amount + fee` in balance requirement | Remote denial of service: a single transaction with `amount = u128::MAX` panicked any node that processed it | All balance and fee arithmetic in `chain.rs` is saturating; hostile amounts are rejected as unaffordable |
| Privileged RPC gate only at the HTTP layer | Non-HTTP entry points could reach operator methods (`inaz_rpcLimits`, `inaz_halt`, `inaz_resume`, `inaz_prune`) | Authorization re-checked inside `dispatch_metered`, failing closed |
| `inaz_netInfo` exposed peer IPs and dial lists | Topology disclosure aiding eclipse attacks | Topology fields require an admin key; anonymous callers get counts only |
| Ambiguous signed-field delimiters | Signature forgery by delimiter injection | Length-prefixed canonical v2 encoding; legacy v1 accepted only when fields contain no delimiter |
| Unvalidated block timestamps | Clock manipulation of leader election | Strict monotonicity plus a 12 s future-drift bound |
| Fork resolution trusted peer height claims | State modification from an uncredible peer | Peer chain credibility verified before any unwind; unwinds bounded by `MAX_REORG_DEPTH` |
| Non-atomic block application | Partial state on a rejected block | Journalled savepoints; a rejected block leaves state bit-identical |

## Operator guidance

- Never run one validator key on two machines — equivocation is tombstoned permanently.
- Keep `--rpc` on localhost unless you intend to serve public traffic.
- Pin peer node keys with `--peer-ids` and set `--require-encrypted-p2p`.
- Store the validator secret in a root-only `EnvironmentFile`, not in the unit file.
