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

### Foundation — complete (`ae39cf3`)

- [x] Schema v6 migration: `policies`, `policy_allowed_domains`,
      `device_policies`. Default policy ships **strict + empty** so
      unassigned devices are blocked by default. Existing
      `allowed_domains` rows intentionally not migrated. Tesla policy
      seeded strict with `connman.vn.tesla.services`.
- [x] `FirewallService` allow-list CRUD rewired onto
      `policy_allowed_domains` via the Default policy.

### Per-policy runtime — complete (`3e3a683`)

- [x] `PolicyService` — CRUD for policies, per-policy allow list,
      device assignment, default-policy lookup.
- [x] `FirewallService.generateConfig` — one nftables set per policy
      (`pol_<id>_ips`), one chain per policy (`pol_<id>_chain`), a
      top-level `forward` dispatch via `ether saddr vmap` using
      `goto` (not `jump`), unassigned MACs fall through to the
      default chain.
- [x] `writeDnsmasqNftsets` — one `nftset=` line per
      (domain × policy); set name derived from policy id.
- [x] Default policy chain behavior matches v1 (accept any IP in its
      set, drop miss).
- [x] Strict policy chain: accept any IP in its set, drop miss — no
      fallback jump to default.

### Reliability — complete (`371c04a`)

- [x] nftset timeout bumped to 30d.
- [x] Periodic re-resolve cron every 6h via
      `PolicyService.StartRefreshLoop`; walks every enabled
      (policy × domain) row and re-queries the local dnsmasq.
- [x] Synchronous resolve on allow-list create — handler fires
      `go policy.ResolveDomain(domain)` after Apply.
- [x] Synchronous flush on allow-list delete — the set definitions
      in `generateConfig` now pre-populate `elements = { ... }` from
      `policy_allowed_domains.resolved_ips`, so a `flush ruleset +
      reload` loads the survivors only, atomically dropping the
      deleted domain's IPs.
- [x] Per-entry metadata — `resolved_ips`, `last_resolved_at` written
      by `ResolveDomain`; `hit_count` column reserved for future use.

### DoH/DoT chokepoint — complete (`51433bb`)

- [x] Bundled 14-IP resolver list in `internal/services/doh.go`
      (Cloudflare, Google, Quad9, AdGuard, OpenDNS, CleanBrowsing,
      ControlD).
- [x] Permanent `doh_resolvers` set populated at Apply.
- [x] Forward-chain drop rule on tcp/443 + udp/853 against that set,
      placed before the per-MAC vmap dispatch. Tagged
      `[NETFILTER-DROP-DOH]` / `[NETFILTER-DROP-DOT]` for the
      traffic monitor.

### API + UI — complete (`371c04a`, `f5a744d`, `6ff7719`)

- [x] Handlers: `GET/POST/PUT/DELETE /api/policies`,
      `GET/POST/DELETE /api/policies/{id}/domains`,
      `PUT/DELETE /api/policies/domains/{domainID}`,
      `PUT/DELETE /api/devices/{mac}/policy`,
      `GET /api/policies/assignments`.
- [x] Traffic-monitor entries now carry `source` (`dns` | `forward`)
      and `policy` columns; schema v7 migration backfills existing
      rows.
- [x] Policies page — list policies, mode + default badges, expand
      to edit allow list (with resolved_ips + last_resolved_at +
      hit_count columns), device-assignment table with inline
      create/delete.
- [x] Device rows (Devices page) gain a policy dropdown that writes
      `/api/devices/{mac}/policy` inline; "Default (inherited)"
      means no explicit assignment.
- [x] Traffic Monitor gains tabs: All / DNS queries / Firewall
      decisions, wired to the `source=` query param.

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

## Status

v2 is feature-complete on the `v2` branch as of 2026-04-19. Branch
ready for validation on the appliance and merge back to `master`
after user sign-off.

## Ordering risks (retained for review)

- Dropping `allowed_domains` in the migration means v1 binaries no
  longer run against a v6 DB. Acceptable — v2 is a forward-only
  upgrade.
- Adding per-MAC dispatch means `FirewallService.Apply` now depends
  on `device_policies`; the `policySnapshot` struct loads everything
  in one transactional sweep at the top of Apply to keep read
  consistency.
