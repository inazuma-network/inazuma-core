# Contributing

This repository holds the Rust node that runs the Inazuma network. Contributions are welcome, including your first one.

## Ways to help that are not code

- Follow a guide, and open an issue anywhere it was confusing or wrong.
- Report a bug with the exact commands you ran and what you saw.
- Improve the docs. Fixing one unclear paragraph is a real contribution.
- Answer someone else's question in the issue tracker.

## Setting up


        ```bash
        git clone https://github.com/inazuma-network/inazuma-core.git
        cd inazuma-core
        cargo build            # compile
        cargo test             # run tests
        cargo fmt --all        # format
        cargo clippy --all-targets -- -D warnings
        ```


## Workflow

1. Open an issue first for anything non-trivial, so nobody duplicates your work.
2. Fork, then branch: `fix/rpc-timeout` or `feat/batch-submit`.
3. Make one logical change per pull request. Small reviews get merged fast.
4. Write commit messages as `area: what changed` — for example `mempool: cap per-account queue`.
5. Fill in the pull request template, including how you tested it.
6. A maintainer reviews. Expect questions; they are not criticism of you.


        ## The activation-height rule

        Any change to consensus, fees, slashing, state layout, or transaction encoding
        must be gated behind a block height, never applied immediately. Old and new nodes
        have to agree on every block that already exists.

        ```rust
        if height >= SLASHING_ACTIVATION_HEIGHT {
            // new behaviour
        } else {
            // exactly the old behaviour, unchanged
        }
        ```

        A pull request that changes consensus without a height will be closed with a
        request to add one. Pick a height at least 50,000 blocks (about 6 hours) ahead of
        the expected release so operators have time to upgrade.

        ## Bigger changes need an INAZIP

        Anything that changes the protocol itself — new transaction types, economic
        parameters, precompiles, cryptography — starts as a proposal in
        [inazuma-improvement-proposals](https://github.com/inazuma-network/inazuma-improvement-proposals).
        Write the proposal first, get it discussed, then send code.


## Reporting security bugs

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## License

By contributing you agree your work is released under the MIT license in
[LICENSE](LICENSE).
