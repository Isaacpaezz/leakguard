---
name: leakguard-add-service
description: "Add or update a protectable service in the leakguard catalog. Trigger: new service, update IP ranges, catalog change, service request issue."
license: MIT
metadata:
  author: Isaacpaezz
  version: "1.0"
---

## When to use

- A `service_request` issue asks to add a service or fix its ranges or domains.
- A protected app talks to a destination the catalog does not cover.

## Critical rules

1. Every range comes from a source you actually opened. Never guess, never "complete" a list from memory.
2. A `supported` service has IPv4 **and** IPv6 ranges, `sources` and a `verified` date.
3. Ranges must be canonical CIDR (`160.79.104.0/23`, not `160.79.104.1/23`).
4. Shared CDN addresses (Cloudflare, Google Cloud, Akamai, Fastly) are never added as ranges. Use `"status": "planned"` with a `notes` line explaining the CDN problem.
5. Do not edit README.md inside the generated markers; regenerate it.

## Steps

1. Find the sources, in this order of preference:
   - the provider's official IP list or documentation;
   - the provider's own ASN prefixes (`https://bgp.he.net/AS<number>#_prefixes`, `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS<number>`);
   - official documentation of the apps (for domains).
2. Write `catalog/services/<id>.json` (the file name must equal the `id`):

   ```json
   {
     "id": "example",
     "name": "Example AI",
     "description": "What apps this covers.",
     "status": "supported",
     "ipv4": ["203.0.113.0/24"],
     "ipv6": ["2001:db8::/32"],
     "domains": ["api.example.com"],
     "sources": ["https://example.com/ip-ranges"],
     "verified": "2026-11-15",
     "notes": "Optional caveats, such as telemetry hosts not covered."
   }
   ```

   Allowed fields: `id`, `name`, `description`, `status` (`supported` or `planned`), `ipv4`, `ipv6`, `domains`, `sources`, `verified`, `notes`. Unknown fields fail validation.
3. Add a line under `[Unreleased]` in `CHANGELOG.md` (for example `- Catalog: add Example AI.`).
4. Run:

   ```sh
   go test ./...
   go run ./tools/readmegen
   go run ./tools/readmegen -check
   ```

5. Open a pull request of type `catalog`. In "How I tested it", list each source and what it showed.

## Done when

- `readmegen -check` prints `README.md is up to date`.
- The README services table shows the new or updated row.
- Every range in the diff can be traced to a link in `sources`.
