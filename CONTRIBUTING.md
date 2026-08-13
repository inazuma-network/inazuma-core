# Contributing

## Build and test

```bash
cargo build --release
cargo test
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

All tests must pass before a pull request is opened. `cargo test` boots an in-process
chain, so no external services are required.

## Consensus-breaking changes

Anything that changes block validity, transaction encoding, fees, state layout or the
state root must be gated behind an **activation height** so existing history replays
unchanged. Never mutate past behaviour in place. Existing gates: slashing at block
130,000, sparse Merkle state at block 200,000.

## Pull requests

- One logical change per PR, with a short description of what and why.
- Include a test for every behaviour change; consensus changes need the replay argument
  spelled out in the description.
- Keep the commit history readable — squash noise before review.

## Local devnet

```bash
inazuma keygen
inazuma init --data ./data --genesis ./genesis.json --admin <ADDRESS> --key <SECRET>
inazuma run  --data ./data --genesis ./genesis.json --key <SECRET> --rpc 127.0.0.1:9933
inazuma bench --key <SECRET> --count 1000
```
