# PBS Coldstart

Audit the recovery path for a Proxmox Backup Server (PBS) that runs as a VM on the Proxmox VE (PVE) host it protects. Generate a portable cold-start runbook before that host fails.

## The failure this targets

If the only PVE host also runs PBS, losing that host can take the backup server offline. One self-hoster described needing to set up a new PBS instance and reconnect the NAS before they could restore VMs and containers. Separately, a Proxmox user lost VM and LXC definitions while disks remained, and another incident described running guests becoming unbootable after their configuration files were lost. [PBS-on-the-same-host recovery question](https://www.reddit.com/r/homelab/comments/1vwvwvb/budget_homelab_disaster_recovery_procedure/) · [lost guest configurations](https://www.reddit.com/r/homelab/comments/1th5dn8/please_back_up_your_homelab/) · [guests left running without definitions](https://www.reddit.com/r/homelab/comments/1okqtso/)

PBS supports reusing an existing datastore on a fresh instance, but its name and path must match, and one datastore cannot be operated by multiple PBS instances at once. If client-side encryption is enabled, its key must be available independently of the failed host. [PBS datastore documentation](https://pbs.proxmox.com/docs/storage.html) · [PBS encryption documentation](https://pbs.proxmox.com/docs/backup-client.html#encryption)

## What it does

- Audits a small TOML manifest for cold-start dependencies: an independent bootstrap host, off-host PVE configuration, NAS/datastore access, and out-of-band encryption-key custody.
- Flags missing or untested steps and the PBS VM's own backup.
- Generates a Markdown recovery checklist for a human operator to complete and review.

The report is based only on facts you declare in the manifest. It does not connect to Proxmox, inspect a datastore, prove a backup is readable, or claim a restore drill passed. It makes no network connections and has no credential fields. The schema rejects unknown field names and field names containing common secret terms; this is not secret detection, and it cannot recognize secret values pasted into ordinary text fields. `key_reference` must be a human-readable pointer, never key material. Keep the manifest private because it contains host and storage names.

## Quick start

Requires Python 3.11 or newer. No third-party Python packages are used.

```sh
python3 pbs_coldstart.py audit examples/homelab.toml
python3 pbs_coldstart.py plan examples/homelab.toml --output recovery-plan.md
```

Copy `examples/homelab.toml` and replace its fictional values. Do not put secrets in the file. The example intentionally contains unresolved warnings.

## Business hypothesis

The free CLI is for a single lab. The paid path to validate is a quarterly cold-start rehearsal and recovery-evidence service for small MSPs managing Proxmox clients, with the CLI generating a consistent, portable report. Existing providers sell emergency Proxmox support and restore testing, which shows a paid service category exists; it does not prove buyers want this specific tool or service. See [the market notes](docs/market-evidence.md).

## Competitive boundary

This is not another backup engine, host-configuration backup tool, or VM restore-testing dashboard. ProxSave and ProxMenux already cover host configuration backup/recovery; AutoRPO and Asternodis cover nearby restore testing or disaster-recovery orchestration. The unvalidated wedge is the PBS bootstrap dependency and off-host key/access path. Stop or pivot if customer interviews show existing tools already prove that path adequately.

## License

MIT. See [LICENSE](LICENSE).
