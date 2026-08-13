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

## Operator guidance

- Never run one validator key on two machines — equivocation is tombstoned permanently.
- Keep `--rpc` on localhost unless you intend to serve public traffic.
- Pin peer node keys with `--peer-ids` and set `--require-encrypted-p2p`.
- Store the validator secret in a root-only `EnvironmentFile`, not in the unit file.
