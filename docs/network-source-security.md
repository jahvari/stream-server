# Network source security

Stream Server protects the `/proxy` endpoint from server-side request forgery (SSRF). By default,
`/proxy` can contact public HTTP and HTTPS destinations only, and HTTPS certificates must be valid.
These defaults prevent a webpage or LAN client that can reach Stream Server from using it to probe
services on your computer, local network, or cloud metadata endpoints.

> **Important:** both security exceptions described below are global policies for every `/proxy`
> request while enabled. They are not per-site allowlists. Any browser or LAN client that can reach
> the Stream Server listener may ask `/proxy` to contact an otherwise eligible private destination.
> Enable an exception only when required, restrict listener access with host firewall and network
> controls, and disable it afterward. Stream Server does not automatically add or change Windows
> Firewall rules.

## Scope of this protection

This policy applies only to `/proxy` in this release. The same destination validator does not yet
protect subtitle downloads, archives or local paths, FTP/curl inputs, NZB/NNTP, non-proxy HLS,
casting or FFmpeg inputs, remote torrent or tracker inputs, BitTorrent-backend fetches, or updater
inputs. Treat those as separate trust boundaries until later security work covers them.

`BitTorrent SSRF mitigation` is also separate. It maps to `btSsrfMitigation`, remains enabled by
default, and controls libtorrent behavior rather than `/proxy`.

## Configure the options in the settings app

Open **Settings > Privacy**. Two protected controls are available:

- **Allow private/LAN proxy sources** lets every `/proxy` request reach eligible loopback, private,
  carrier-grade NAT, IPv6 ULA, IPv4 link-local, and directly connected sources. Known metadata and
  other always-blocked addresses remain denied.
- **Allow invalid proxy TLS certificates** disables certificate verification for every `/proxy`
  request. Enable it only when a required source uses a certificate you have independently trusted.

The standalone settings app enables these controls only when it connects to an IP-literal loopback
address and can read the local `settings-control.token` file. The embedded tray settings window is
trusted directly. A remote settings connection can still read settings and change ordinary options,
but cannot change either protected option.

The invalid-certificate option does not broaden the address policy. A self-signed private source
requires both exceptions. Prefer a valid certificate whenever possible.

## Configure the local HTTP API

Protected changes require all of the following:

1. Connect directly from loopback (`127.0.0.1` or `::1`).
2. Read the per-install token from the configuration directory without printing it.
3. Send it in `x-stream-server-settings-token`.
4. Send JSON booleans for the protected options.

On Windows PowerShell:

```powershell
$tokenPath = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'stremio-server\settings-control.token'
$settingsToken = (Get-Content -Raw -LiteralPath $tokenPath).TrimEnd("`r", "`n")
$headers = @{ 'x-stream-server-settings-token' = $settingsToken }
$body = @{ allowPrivateNetworkSources = $true; allowInvalidProxyTlsCertificates = $false } | ConvertTo-Json -Compress
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:11470/settings' -Headers $headers -ContentType 'application/json' -Body $body
Remove-Variable settingsToken, headers, body
```

On Linux with `curl`:

```sh
token_file="${XDG_CONFIG_HOME:-$HOME/.config}/stremio-server/settings-control.token"
settings_token="$(tr -d '\r\n' < "$token_file")"
curl --fail-with-body --request POST 'http://127.0.0.1:11470/settings' \
  --header "x-stream-server-settings-token: ${settings_token}" \
  --header 'content-type: application/json' \
  --data '{"allowPrivateNetworkSources":true,"allowInvalidProxyTlsCertificates":false}'
unset settings_token
```

On macOS with `curl` (the quoted path normally contains a space):

```sh
token_file="$HOME/Library/Application Support/stremio-server/settings-control.token"
settings_token="$(tr -d '\r\n' < "$token_file")"
curl --fail-with-body --request POST 'http://127.0.0.1:11470/settings' \
  --header "x-stream-server-settings-token: ${settings_token}" \
  --header 'content-type: application/json' \
  --data '{"allowPrivateNetworkSources":true,"allowInvalidProxyTlsCertificates":false}'
unset settings_token
```

The token is not returned by the settings API or included in diagnostics exports. Treat the token
file as a local secret; do not paste it into logs, issue reports, or configuration files.

## Configure files or environment variables

The equivalent `settings.json` keys are:

```json
{
  "allowPrivateNetworkSources": false,
  "allowInvalidProxyTlsCertificates": false
}
```

Stop Stream Server before editing `settings.json`, then restart it. The server also accepts these
environment variables:

- `STREMIO_ALLOW_PRIVATE_NETWORK_SOURCES`
- `STREMIO_ALLOW_INVALID_PROXY_TLS_CERTIFICATES`

Accepted values are `1`, `true`, `yes`, or `on`, and `0`, `false`, `no`, or `off`, without leading
or trailing whitespace and case-insensitively. Environment values override the persisted file at
startup. A runtime GUI/API change can affect the current process, but the environment value wins
again after the next restart. Environment-only values are not copied into `settings.json` by
ordinary settings changes, tracker-cache updates, or background saves; removing the environment
variable therefore restores the persisted value on the next restart.

## Destination policy

| Destination class | Default | With private/LAN opt-in |
| --- | --- | --- |
| Public HTTP/HTTPS address | Allowed | Allowed |
| Loopback and private address | Blocked | Allowed |
| CGNAT, IPv6 ULA, IPv4 link-local, and current connected network | Blocked | Allowed |
| Stream Server's registered HTTP/HTTPS listeners | Blocked | Blocked |
| Known cloud, container, and platform metadata addresses | Blocked | Blocked |
| Unspecified, multicast, broadcast, documentation, benchmark, reserved, or future-use address | Blocked | Blocked |

Every DNS answer must pass the policy; one unsafe answer blocks the destination. Validated socket
addresses are pinned into a fresh outbound client that ignores system HTTP proxies. Every redirect
is resolved, revalidated, and pinned again, and HTTPS-to-HTTP downgrades are blocked.

IPv4 link-local sources require the private/LAN exception, but known metadata addresses remain
blocked even with that exception. Resolver-supplied IPv6 link-local addresses require a nonzero
interface scope and retain that scope when pinned. Scoped IPv6 URL literals are not supported.
Meaningless scope and flow identifiers on non-link-local IPv6 addresses are normalized away.

The only NAT64 prefix interpreted without network discovery is the well-known `64:ff9b::/96`
prefix. Network-specific prefixes are accepted only after strict discovery through the absolute DNS
name `ipv4only.arpa.` and recognition of both required `192.0.0.170` and `192.0.0.171` embeddings.
The full `64:ff9b:1::/48` reservation is not treated as an embedding rule without that discovery.
Successful and failed discovery results are cached briefly and bound to the current per-address
network-interface identity; an interface or address assignment change invalidates the cache. A
global or eligible ULA IPv6 destination that requires discovery fails closed while discovery is
unavailable. The well-known prefix remains independently classifiable.

Exact current interface addresses and all registered listener sockets are checked in their native,
IPv4-mapped, and discovered NAT64 forms. Applications that call `build_router` but serve the router
on additional sockets must instead call `build_router_with_listeners` and provide every actual
listener address; otherwise the validator cannot identify those caller-owned sockets.

Each server runtime creates a random sensitive hop marker and overwrites that internal header on
every outbound proxy hop. A matching marker returning to the application is rejected before `/proxy`
or non-proxy route handlers run. An outer CORS `OPTIONS` preflight remains an empty local response: it
does not dispatch upstream or consume proxy capacity. A reverse proxy that strips the hop marker, or
a separately constructed router with an independent runtime marker, remains a loop risk unless the
registered listener identity also blocks it.

## Capacity and timeout limits

- Active proxy requests: 64 globally and 16 per normalized client address.
- Playlist transformations: 8 globally and 4 per normalized client address, in addition to the
  active-request limit.
- Upstream response headers and read-idle periods: 30 seconds per hop/period.
- A full downstream handoff slot: 120 seconds without consumption.
- Playlist collection and delivery each have fixed 120-second lifecycle deadlines; bounded blocking
  rewrite work observes cooperative cancellation.
- A capacity rejection returns `503 Proxy capacity is exhausted` with `Retry-After: 1`.

Ordinary media streams do not have a fixed total lifetime: continued downstream progress permits
long playback. Dropped, cancelled, idle, or stalled bodies release their producer-owned permits.
Playlist input and output are separately bounded, and rewrite work runs off the asynchronous runtime.

## Redirects, headers, playlists, and browser isolation

On a cross-origin redirect, Stream Server clears caller-supplied request headers, URL userinfo, and
`If-Range`; `Range` is retained for media/CDN compatibility. Each new origin still undergoes the full
destination and TLS policy. Credential-bearing or rewritten responses are forced to
`Cache-Control: private, no-store`.

All proxy success and error responses receive route-owned active-content isolation headers,
including a restrictive sandboxed Content Security Policy, `nosniff`, `no-referrer`, and frame
denial. Custom response headers are narrowly validated and cannot replace these controls.

Full `200` HLS playlists may be safely rewritten. An upstream `Cache-Control: no-transform`, a raw
`206 Partial Content` response, `HEAD`, or a non-success status stays on the unmodified streaming
path. Rewritten bodies remove stale length/range/encoding/validator metadata, disable ranges, and
use private non-storable caching. Raw `206` framing and validators are preserved because its bytes
are not transformed.

These controls do not make a publicly reachable Stream Server a safe general-purpose application
proxy. Browser clients that can reach the listener can still request any destination allowed by the
current global policy and can consume server bandwidth and capacity. Keep the listener and firewall
exposure as narrow as your installation permits.

## Troubleshooting

- `400 Invalid proxy request`: the URL/options are malformed, use an unsupported scheme, contain an
  unsafe custom header, or exceed an input limit.
- `403 Proxy destination is blocked`: an address, redirect, self-listener, metadata destination, or
  returned hop marker is denied. Enable private/LAN sources only if the source and every reachable
  browser/LAN client are trusted for this global exception.
- HTTP `403` JSON from `POST /settings`: a protected value changed without a valid local token, or
  the request did not originate from loopback.
- `502 Proxy upstream request failed`: DNS, TLS, connection, redirect, response encoding, playlist
  size, collection/rewrite, or timeout validation failed. A self-signed source may require the TLS
  exception.
- `503 Proxy capacity is exhausted`: a global, per-client, or playlist quota is full. Retry after the
  response's `Retry-After` delay.
