# NetFilter v2 — roadmap

## Why v2

v1 uses a single global allow-list populated into one nftables IP set
(`allowed_domains`) via dnsmasq's `nftset=` integration. This has three
user-visible failure modes that accumulated over testing:

1. **"Allowed but still blocked"** — the IP set has a 1-hour timeout and is
   only populated when dnsmasq sees a fresh DNS query. Cached DNS answers
   (browser cache, OS cache, dnsmasq cache) don't re-populate, so the
   forward chain drops packets for an IP that aged out between queries.
2. **CDN bleed** — CloudFront/Akamai IPs are shared across thousands of
   distributions. Allowing `api.anthropic.com` implicitly allows
   `d2kx5qi9c9o4mb.cloudfront.net` and any other co-located tenant.
3. **Flat policy model** — there is no way to say "the Tesla can only
   reach connman; my phone can reach anything." One list, one policy,
   one verdict.

## What v2 delivers

- **Named policies** with `mode` (permissive / strict). Each policy has
  its own allow list and its own nftables set.
- **Per-device assignment** — a device's MAC maps to a single policy;
  unmapped devices inherit the `Default` policy.
- **Strict mode** — policy chain has no fallback; only allow-listed IPs
  reach WAN, everything else drops. Tesla policy is strict by seed.
- **Reliability fixes** — 30-day nftset timeout with a periodic
  re-resolve cron; synchronous resolve + nftset populate on allow
  create; synchronous flush on delete.
- **DoH/DoT chokepoint** — drop known encrypted-DNS resolvers at the
  forward chain so clients can't bypass dnsmasq.
- **Traffic monitor split** — DNS events (dnsmasq log) and forward
  events (nflog) in separate tabs, never mixed.
- **Policies UI** — CRUD, per-policy allow list, device assignment.

## Implementation order

Each bullet = one commit. Each commit keeps the tree green (`go build`
passes and the running daemon boots).

### Foundation (complete — commit pending on `v2` branch)

- [x] Schema v6 migration: `policies`, `policy_allowed_domains`,
      `device_policies`. Data migration: existing `allowed_domains`
      rows move into the `Default` policy; `Tesla` policy seeded with
      `connman.vn.tesla.services`.
- [x] `FirewallService` allow-list CRUD now operates on the `Default`
      policy via `policy_allowed_domains`. Behavior unchanged for v1
      API clients.

### Per-policy runtime (next)

- [ ] `PolicyService` — CRUD for policies, per-policy allow list,
      device assignment.
- [ ] `FirewallService.generateConfig` — one nftables set per policy
      (`pol_<id>_ips`), one chain per policy (`pol_<id>_chain`), a
      top-level `forward` dispatch via `ether saddr vmap`.
- [ ] `writeDnsmasqNftsets` — one `nftset=` line per
      (domain × policy); the nft set name derived from policy id.
- [ ] Default policy chain behavior matches v1 (accept any IP in its
      set, drop miss).
- [ ] Strict policy chain: accept any IP in its set, drop miss — no
      fallback jump to default.

### Reliability (next+1)

- [ ] Bump nftset timeout to 30d.
- [ ] Periodic re-resolve cron (every 6h) that walks
      `policy_allowed_domains` and issues DNS queries through
      127.0.0.1 so dnsmasq re-populates the sets.
- [ ] Synchronous resolve on allow-list create: block the HTTP
      request until the first DNS query has pushed IPs into the set.
- [ ] Synchronous flush on allow-list delete: remove matching IPs
      from the set before returning 200.
- [ ] Per-entry metadata — write `resolved_ips`, `last_resolved_at`,
      `hit_count` as the cron runs.

### DoH/DoT chokepoint

- [ ] Bundled resolver list in `internal/services/doh.go`
      (IPs for `1.1.1.1`, `1.0.0.1`, `8.8.8.8`, `8.8.4.4`, `9.9.9.9`,
      `149.112.112.112`, `94.140.14.14`, `94.140.15.15`, ...).
- [ ] `doh_resolvers` set, permanent, populated once at startup.
- [ ] Forward-chain drop rule on tcp/443 + udp/853 against that set
      runs before any policy chain jumps.

### API + UI

- [ ] Handlers: `GET/POST/PUT/DELETE /api/policies`,
      `GET/POST/DELETE /api/policies/:id/domains`,
      `PUT /api/devices/:mac/policy`.
- [ ] Traffic-monitor endpoint returns `source` (`dns` | `forward`)
      so the UI can tab-split without server changes per render.
- [ ] Policies page (list, create, edit mode, edit allow list).
- [ ] Device rows gain a policy dropdown.
- [ ] Allow-list row shows last-resolved IPs + hit count + retry
      button.

## Data model (v6)

```
policies (id, name UNIQUE, mode ∈ {permissive,strict},
          description, is_default, created_at)

policy_allowed_domains (id, policy_id FK→policies,
                        domain, description, enabled,
                        resolved_ips, last_resolved_at, hit_count,
                        created_at, UNIQUE(policy_id, domain))

device_policies (device_mac PK, policy_id FK→policies, assigned_at)
```

Seed: `Default` (permissive, is_default=1) + `Tesla` (strict, seeded
with `connman.vn.tesla.services`).

## nftables shape (target)

```nft
table inet filter {
    set pol_1_ips { type ipv4_addr; flags timeout; timeout 30d; }  # Default
    set pol_2_ips { type ipv4_addr; flags timeout; timeout 30d; }  # Tesla
    set doh_resolvers { type ipv4_addr; }

    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept

        # DoH/DoT chokepoint — applies to every device regardless of policy
        ip daddr @doh_resolvers tcp dport 443 drop
        ip daddr @doh_resolvers udp dport 853 drop

        # Dispatch by MAC → policy chain
        ether saddr vmap {
            AA:BB:CC:DD:EE:FF : jump pol_2_chain,   # Tesla
        }

        # Fallback: Default policy chain
        jump pol_1_chain
    }

    chain pol_1_chain {                              # Default, permissive
        ip daddr @pol_1_ips log prefix "[NF-ACCEPT] " accept
        ct state new log prefix "[NF-DROP] "
    }

    chain pol_2_chain {                              # Tesla, strict
        ip daddr @pol_2_ips log prefix "[NF-ACCEPT] " accept
        ct state new log prefix "[NF-DROP-TESLA] "
    }
}
```

(Permissive vs strict are structurally identical when a device is
pinned to a policy; the distinction matters only for unmapped devices,
which always fall back to Default. Strict mode's real value is
conceptual: it signals to the operator "this list is complete.")

## Ordering risks

- Dropping `allowed_domains` in the migration means v1 binaries no
  longer run against a v6 DB. Acceptable — v2 is a forward-only
  upgrade.
- The `INSERT OR IGNORE` data-migration relies on the Default policy
  existing before the copy; the migration script ordering is correct.
- Adding per-MAC dispatch means the firewall re-apply now depends on
  the `devices` and `device_policies` tables. `FirewallService.Apply`
  will need to join these.
