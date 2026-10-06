# Regional subnet supplements and voice exclusions

Reviewed 2026-10-03. These supplements accompany the external game-network feed:

| CIDR | Group | Evidence and limitations |
| --- | --- | --- |
| `66.40.191.0/24` | Netherlands (`ams1`) | RIPEstat currently reports this route originated by AS57976 Blizzard. User observed `66.40.191.240`; IPinfo and ipwho.is place that peer in Amsterdam. Classification of the entire route as an Amsterdam game pool remains an inference. |
| `5.42.168.0/21` | Netherlands (`ams1`) | MINA's Amsterdam configuration lists `5.42.168.0–5.42.175.255`. The current route for `.168.1` is `5.42.168.0/22`, AS57976, with Amsterdam geolocation. The broader /21 comes from a community list, not a fresh Blizzard guarantee. |

Sources:

- https://stat.ripe.net/data/network-info/data.json?resource=66.40.191.240
- https://rdap.arin.net/registry/ip/66.40.191.240
- https://ipinfo.io/66.40.191.240/json
- https://ipwho.is/66.40.191.240
- https://github.com/foryVERX/Overwatch-Server-Selector/blob/main/ip_lists/cfg%20-%20EU%20-%20Netherlands%20-%20AMS1.txt
- https://stat.ripe.net/data/network-info/data.json?resource=5.42.168.1
- https://ipinfo.io/5.42.168.1/json

The registered Blizzard allocation `66.40.176.0/20` is not blocked wholesale:
ownership does not establish that all its addresses belong to this game region.
The community EU lists include Finland and other locations; they cannot be
assigned wholesale to Amsterdam while preserving Finland-only selection.

## Vivox must never be a game-region block

The [official Unity article](https://support.unity.com/hc/en-us/articles/4407491745940-Vivox-What-IPs-and-ports-are-required-for-Vivox-to-work), updated August 6, 2026,
identifies `85.236.96.0/21` and `85.236.104.0/23` as Vivox ranges, using UDP
12000–54000 for voice media. The previous `85.236.97.71/32` US-east addition
was misclassified and has been removed.

Both the TUI data loader and privileged helper subtract these ranges, including
from a larger enclosing CIDR. These are exclusions from Dropshit's own rules,
not ACCEPT rules overriding the system firewall. Startup authenticated status
checks and boot restore clean old saved voice blocks and update saved state.
After upgrading, reopen Dropshit and authorize its initial status check.
Outdated selections are reapplied automatically; `a` retries after an error.

Rules match per-user UDP destination ports 12000–19293 and 19345–49999.
Discord destination ports 1541, 19294–19344 and 50000–65535 are excluded.
One allowed region uses its strict allowlist plus Vivox and Discord exceptions;
two or more use the regional blocklist with the same exceptions.
