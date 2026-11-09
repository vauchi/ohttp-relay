<!-- SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me> -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

> **Mirror:** This repo is a read-only mirror of [gitlab.com/vauchi/ohttp-relay](https://gitlab.com/vauchi/ohttp-relay). Please open issues and merge requests there.

# Vauchi OHTTP Relay

A minimal Oblivious HTTP (RFC 9458) forwarding proxy for the
[Vauchi relay](https://gitlab.com/vauchi/relay). It passes encapsulated
requests from clients to the gateway, so the relay that handles a request
does not see the client's address. The privacy holds only when the OHTTP
relay and the gateway are run by different operators; until the first
release one operator runs both. The protocol is specified in
[vauchi/spec](https://gitlab.com/vauchi/spec).

## Run

```sh
OHTTP_RELAY_GATEWAY_URL=https://gateway.example/ cargo run --release
```

It listens on `OHTTP_RELAY_LISTEN_ADDR` (default `0.0.0.0:8082`).

## Security

See [SECURITY.md](SECURITY.md).

## License

AGPL-3.0-or-later; see `LICENSE` and `REUSE.toml`.
