# Network source security

Stream Server protects the `/proxy` endpoint from server-side request forgery (SSRF). By default,
`/proxy` can contact public HTTP and HTTPS destinations only, and HTTPS certificates must be valid.
These defaults prevent a webpage or LAN client that can reach Stream Server from using it to probe
services on your computer, local network, or cloud metadata endpoints.

This protection applies to `/proxy` only. Subtitle, archive, FTP, NZB/NNTP, HLS/casting, remote
torrent, tracker, and updater network inputs are outside this policy.

## Configure the options in the settings app

Open **Settings > Privacy**. Two protected controls are available:

- **Allow private/LAN proxy sources** lets `/proxy` reach loopback, private, link-local, CGNAT,
  IPv6 ULA, and directly connected network sources. Enable it only for a media source you trust.
- **Allow invalid proxy TLS certificates** disables certificate verification for `/proxy` only.
  Enable it only for a trusted self-signed HTTPS source.

The standalone settings app enables these controls only when it connects to an IP-literal loopback
address and can read the local `settings-control.token` file. The embedded tray settings window is
trusted directly. A remote settings connection can still read settings and change ordinary options,
but cannot change either protected option.

`BitTorrent SSRF mitigation` is separate. It maps to `btSsrfMitigation`, remains enabled by
default, and controls libtorrent behavior rather than `/proxy`.

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

On Linux or macOS with `curl`:

```sh
token_file="${XDG_CONFIG_HOME:-$HOME/.config}/stremio-server/settings-control.token"
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
again after the next restart.

## Destination policy

| Destination class | Default | With private/LAN opt-in |
| --- | --- | --- |
| Public HTTP/HTTPS address | Allowed | Allowed |
| Loopback and RFC 1918 private address | Blocked | Allowed |
| CGNAT, IPv6 ULA, and non-metadata link-local address | Blocked | Allowed |
| Current directly connected network | Blocked | Allowed |
| Stream Server's own HTTP/HTTPS listener | Blocked | Blocked |
| Known cloud/container metadata address | Blocked | Blocked |
| Unspecified, multicast, broadcast, documentation, benchmark, reserved, or future-use address | Blocked | Blocked |

Every DNS answer and every redirect destination must pass the policy. Stream Server pins validated
DNS results to the outbound connection, ignores system HTTP proxies for `/proxy`, blocks HTTPS to
HTTP redirect downgrades, and never permits its own listener through the proxy.

The invalid-certificate option does not broaden the address policy. For example, a self-signed LAN
source requires both the private/LAN option and the invalid-certificate option. Prefer installing a
valid certificate whenever possible.

## Troubleshooting

- `400 Invalid proxy request`: the URL/options are malformed, use an unsupported scheme, contain an
  unsafe custom header, or exceed an input limit.
- `403 Proxy destination is blocked`: the resolved address, a redirect, or the server's own listener
  is denied. Enable private/LAN sources only if the destination is a trusted local media source.
- HTTP `403` JSON from `POST /settings`: a protected value changed without a valid local token, or
  the request did not originate from loopback.
- `502 Proxy upstream request failed`: DNS, TLS, connection, redirect, response encoding, playlist
  size, or read timeout validation failed. A self-signed source may require the TLS opt-in.
- `503 Proxy capacity is exhausted`: 64 proxy requests are already active. Retry after the response's
  `Retry-After` delay.
