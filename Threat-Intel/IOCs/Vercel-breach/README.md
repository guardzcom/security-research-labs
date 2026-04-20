# IOC Package: Vercel April 2026 security incident

**Purpose:** Hard indicators published in connection with [Vercel’s April 2026 security incident](https://vercel.com/security), for threat intelligence, log review, and Google Workspace / OAuth integration auditing. **Scope and impact guidance belong to Vercel’s official communications**, so use this file as an IOC index, not as a substitute for their customer notices.

**Authorized use only.** Handle per your classification and sharing policies.

---

## Incident context (high level)

Vercel confirmed unauthorized access to certain internal systems. Public reporting and Vercel’s security materials describe customer impact as **limited to a subset of accounts** and emphasize **credential rotation**, **review of third-party access**, and verification of official updates. The indicators below tie to a **Google OAuth client** associated with a third-party vendor workflow referenced in open reporting on the incident.

---

## Hard IOCs

| Type | Value |
|------|--------|
| Hard IOC | Google OAuth `client_id`: `110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com` |
| Hard IOC | Google project prefix: `110671459871` |
| Hard IOC | App display name: **Context App** |
| Hard IOC | Upstream vendor: **Context.ai** |

---

## Defensive notes (operational)

- **Google Workspace / Cloud:** Search admin audit logs and OAuth token grants for the `client_id` above; inventory installed marketplace or domain-wide delegated apps that match the display name or vendor.
- **Broader org:** If your teams used the same vendor integration pattern, treat matching consent or refresh-token activity as **high-priority review**, not automatic compromise, and correlate with Vercel’s guidance and your own change records.
- **Follow Vercel:** Rotate and scope credentials per [Vercel Security](https://vercel.com/security) and any direct notices to your organization.

---

## Primary reference

- [Vercel Security](https://vercel.com/security) (includes the April 2026 security incident)

---

## License

Same as the root repository, see [../../../LICENSE](../../../LICENSE).
