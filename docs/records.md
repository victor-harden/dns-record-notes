# DNS records in security work

| Type | Meaning | Why it matters |
|---|---|---|
| A / AAAA | Host to IPv4/IPv6 | Ownership, hosting provider, dangling records |
| CNAME | Alias | Dangling CNAMEs can be taken over |
| MX | Mail exchangers | Mail flow, spoofing surface |
| TXT | Free text | SPF, DKIM, DMARC, verification tokens |
| NS | Delegation | Who controls the zone |
| CAA | Allowed CAs | Restricts certificate issuance |
| SOA | Zone authority | Serial, refresh, contact |

## What to check on an assessment

- SPF ends in `-all` or `~all` with a reviewed include list.
- DMARC policy is `p=reject` or at least `p=quarantine` with reporting.
- DKIM selectors exist and rotate.
- CAA restricts issuance to your CA.
- No records point to decommissioned cloud resources.
