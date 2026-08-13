# Governance

## Short version

Code is merged by maintainers. Protocol rules change only through a written proposal
(an INAZIP), a release, and an activation height that validators choose to run.
Nobody can change the rules of the running network by merging a pull request.

## Who decides what

| Decision | Who | How |
| --- | --- | --- |
| Bug fixes, docs, tooling | Maintainers | Normal pull request review |
| New RPC methods, non-consensus features | Maintainers | Pull request, plus an issue for discussion first |
| Consensus, fees, staking, slashing, encoding | Network | INAZIP → implementation → release → validators upgrade |
| Emergency fix for an active exploit | Maintainers, publicly disclosed after | Patch release, advisory within 72 hours |

## How a protocol change actually ships

```text
1. Idea            open a draft INAZIP describing the problem and the rule change
2. Review          public discussion; specification made precise enough to implement
3. Implementation  code in inazuma-core, gated behind an activation height
4. Release         tagged version, changelog, and the target block number
5. Adoption        validators upgrade before that block; the rule turns on by itself
6. Live            nodes that did not upgrade fall out of consensus at that block
```

The activation height is the safety valve. Validators running >2/3 of stake have to
be on the new version by that block for it to matter, so upgrades are opt-in in
practice, not imposed.

## Maintainers

Maintainers are contributors with a sustained record of good reviews and shipped
work. They are added by agreement of existing maintainers, announced in the
changelog, and removed the same way if they go inactive or break the code of
conduct.

Responsibilities: review pull requests, keep releases tagged and documented, handle
security reports inside the timelines in [SECURITY.md](SECURITY.md), and keep
discussions public.

## Rules maintainers hold themselves to

- No consensus change without an activation height.
- No silent changes to economics — supply, fees, rewards and slashing parameters are
  documented before they ship.
- Security advisories are published after a fix, not buried.
- Discussion happens in public issues, not private chat, unless it is a live
  vulnerability.

## Disagreement

If you think a decision is wrong, say so in the issue with your reasoning. If it is
still unresolved, the fallback is the same as every open network: fork the code, run
your version, and let validators pick. That option existing is the point.
