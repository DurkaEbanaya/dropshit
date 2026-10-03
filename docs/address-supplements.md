# Exact-address supplements

Dropshit supplements the external game-network feed with these **exact /32s**,
reported by a user as live Overwatch peers and absent from the feed at review.
No surrounding allocation is blocked by this supplement.

| Peer | Geographic grouping in Dropshit | Ownership | Reviewed |
| --- | --- | --- | --- |
| `66.40.191.240/32` | Netherlands (`ams1`) | AS57976, Blizzard Entertainment | 2026-10-03 |
| `85.236.97.71/32` | US east (`gue4`) | AS35028, Unity Technologies ApS | 2026-10-03 |

Both IPinfo and ipwho.is returned Amsterdam, Netherlands for the first address
and Boston, Massachusetts, US for the second:

- https://ipinfo.io/66.40.191.240/json
- https://ipwho.is/66.40.191.240
- https://ipinfo.io/85.236.97.71/json
- https://ipwho.is/85.236.97.71

These databases provide a geographic estimate, not proof of a physical server
location or its matchmaker datacenter code. `gue4` is the existing UI's US-east
grouping; the Boston peer is not verified as a `gue4` game server. The Unity
address may carry voice/service traffic. Blocking that region also blocks this
peer's UDP ports 12000–64000 and may interrupt voice communication. TCP and UDP
outside that port range remain unaffected.

The additions use the same selection, apply, nftables/iptables and persistence
paths as the external CIDRs. A subsequent upstream CIDR containing a peer
supersedes its extra /32. A saved selection with outdated network coverage is
marked as unapplied: press `a` to update it after upgrading or refreshing data.
Finland-only is still a blocklist of known other regions, not an allowlist of
every possible Overwatch destination.
