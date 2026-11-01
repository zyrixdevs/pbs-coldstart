# Problem and market evidence

## User-reported recovery failures

- **August 24, 2026 — PBS bootstrap dependency:** a homelab operator asked how to recover when PBS runs on the same host as PVE and said a disaster would require setting up new PBS and connecting the NAS before VM/LXC restores could begin. [Reddit thread](https://www.reddit.com/r/homelab/comments/1vwvwvb/budget_homelab_disaster_recovery_procedure/)
- **May 18, 2026 — lost configurations:** a homelab user reported losing a year of VM/LXC configurations and application setup after a storage operation. [Reddit thread](https://www.reddit.com/r/homelab/comments/1th5dn8/please_back_up_your_homelab/)
- **October 31, 2025 — live guests, missing definitions:** after losing PVE configuration files, the guests remained running but could not be rebooted; the backups were stale and no restore practice existed. [Reddit thread](https://www.reddit.com/r/homelab/comments/1okqtso/)
- **March 20, 2026 — Compose recovery drift:** a self-hoster found full-stack recovery involved service-specific cleanup, volume ordering, and changed environment values, taking hours longer than expected. [Reddit thread](https://www.reddit.com/r/selfhosted/comments/1rz89tt/good_backup_does_not_mean_good_recovery/)

These posts establish examples of pain, not market size or willingness to pay.

## Product boundary

Generic backup integrity and VM restore testing are crowded. PBS verifies datastore data; ProxSave and ProxMenux cover host configuration backup/recovery; AutoRPO and Asternodis sell adjacent recovery-test or DR orchestration capabilities. This project limits itself to the pre-incident cold-start dependency plan for a PBS VM whose datastore lives outside the protected PVE host: independent bootstrap target, datastore name/path reuse, off-host PVE configuration, key custody, and critical guest restore order.

## Paid path hypothesis

Proxmox specialists sell emergency support and restore-rehearsal services. For example, [croit lists emergency support](https://www.croit.io/services/emergency-support) and [WZ-IT lists Proxmox restore tests](https://wz-it.com/en/expertises/proxmox/support). These are evidence of a paid service category, not proof that buyers will pay for this CLI. Validate the specific need with small MSPs before adding hosted reporting or setting prices.

## Discovery questions

1. In the last PVE outage, what had to be rebuilt before the first VM could be restored?
2. Does PBS run on a protected PVE host? Where does its datastore physically live?
3. Has the datastore been reattached to a fresh PBS instance using the exact reuse procedure? When and on what hardware?
4. Can an operator retrieve the client-side encryption key without PVE, PBS, or the main password vault being available?
5. Which critical guests were restored, how long did it take, and what broke?
6. Who owns the budget for a scheduled rehearsal, and would they commit to a paid pilot?
