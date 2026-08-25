# tcpip-stack

A user-space TCP/IP stack for Linux, built as an experiment in AI-assisted systems engineering.

⚠ **Nothing is implemented yet.** This repository currently holds only the working agreement
(`CLAUDE.md`, `.claude/`) that the implementation will be built under.

## Why this exists

Two repositories, one workflow:

```
                 AI-assisted engineering
                           |
          +----------------+----------------+
          |                                 |
       konjaku                        tcpip-stack
     web / UX / product             C / Linux / RFC
     arguable answers               pinned-down answers
          |                                 |
          +----------------+----------------+
                           |
              the same rules, checks and telemetry
```

The question is whether a way of working that holds where the right answer is arguable
still holds where the right answer is written down in an RFC and visible on the wire.

⚠ **What proves general across both gets extracted into `claude-dev-template`.**
⚠ **What is specific to one domain stays in that repository.**

## Environment

Linux is the source of truth for development. The stack talks to the kernel through
`/dev/net/tun`, and the test environment is built out of network namespaces so that
experiments cannot disturb ordinary networking.

Development tooling is Node (the hooks under `.claude/` use only Node built-ins —
there are no npm dependencies). The product itself is C.

## First milestone

**Our own code answers a ping.** Not TCP — ethernet frames, ARP, IPv4, ICMP echo,
through a TAP device, inside a namespace, verified against `ping` and `tcpdump`.

## Where things are written down

| Question | File |
|---|---|
| How do we work? | [`CLAUDE.md`](CLAUDE.md) |
| How do we write it? | [`.claude/rules/`](.claude/rules/) |
| What may we claim? | [`docs/SPEC.md`](docs/SPEC.md) |
| Why was it decided that way? | [`docs/adr/`](docs/adr/) |

## Licence

Not decided yet.
