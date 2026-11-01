#!/usr/bin/env python3
"""Audit PBS cold-start declarations and produce an operator runbook."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
import tempfile
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SENSITIVE_FIELD_PARTS = (
    "password",
    "token",
    "credential",
    "secret",
    "private_key",
    "key_data",
    "encryption_key",
)

ALLOWED_FIELDS = {
    "manifest": {
        "schema_version", "system_name", "pve_host", "pbs_host",
        "pbs_is_vm_on_protected_pve", "pbs_vm_id", "bootstrap_host",
        "bootstrap_host_independent", "pve_config_backup_off_host",
        "pbs_config_backup_off_host", "pbs_vm_backup_in_datastore",
        "datastore", "encryption", "critical_guests",
    },
    "datastore": {"name", "mount_path", "independent_of_pve", "accessible_without_pve", "fresh_instance_reuse_tested"},
    "encryption": {"client_side_encryption", "key_reference", "key_available_without_pve", "key_available_without_pbs"},
    "critical_guests": {"vmid", "name", "backup_reference", "restore_drill_completed"},
}


@dataclass(frozen=True)
class Finding:
    level: str
    check: str
    detail: str
    action: str


def reject_secret_fields(value: Any, path: str = "manifest") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).lower().replace("-", "_")
            if any(part in normalized for part in SENSITIVE_FIELD_PARTS):
                raise ValueError(f"{path}.{key} is not allowed; store only a secret reference")
            reject_secret_fields(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            reject_secret_fields(nested, f"{path}[{index}]")


def require_string(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > 240 or "\n" in value or "\r" in value:
        raise ValueError(f"{key} must be a non-empty string")
    return value.strip()


def reject_unknown_fields(data: dict[str, Any], allowed: set[str], section: str) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise ValueError(f"unsupported field in {section}: {sorted(unknown)[0]}")


def require_bool(data: dict[str, Any], key: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be true or false")
    return value


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as source:
            manifest = tomllib.load(source)
    except OSError as error:
        raise ValueError(f"cannot read manifest: {error.strerror}") from None
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"invalid TOML: {error}") from None

    reject_secret_fields(manifest)
    reject_unknown_fields(manifest, ALLOWED_FIELDS["manifest"], "manifest")
    if manifest.get("schema_version") != 1:
        raise ValueError("schema_version must be 1")
    for key in ("system_name", "pve_host", "pbs_host", "bootstrap_host"):
        require_string(manifest, key)
    if not isinstance(manifest.get("pbs_vm_id"), int):
        raise ValueError("pbs_vm_id must be an integer")
    for key in (
        "pbs_is_vm_on_protected_pve",
        "bootstrap_host_independent",
        "pve_config_backup_off_host",
        "pbs_config_backup_off_host",
        "pbs_vm_backup_in_datastore",
    ):
        require_bool(manifest, key)

    datastore = manifest.get("datastore")
    if not isinstance(datastore, dict):
        raise ValueError("[datastore] section is required")
    reject_unknown_fields(datastore, ALLOWED_FIELDS["datastore"], "datastore")
    require_string(datastore, "name")
    require_string(datastore, "mount_path")
    for key in ("independent_of_pve", "accessible_without_pve", "fresh_instance_reuse_tested"):
        require_bool(datastore, key)

    encryption = manifest.get("encryption")
    if not isinstance(encryption, dict):
        raise ValueError("[encryption] section is required")
    reject_unknown_fields(encryption, ALLOWED_FIELDS["encryption"], "encryption")
    require_bool(encryption, "client_side_encryption")
    for key in ("key_available_without_pve", "key_available_without_pbs"):
        require_bool(encryption, key)
    if encryption["client_side_encryption"]:
        require_string(encryption, "key_reference")

    guests = manifest.get("critical_guests", [])
    if not isinstance(guests, list):
        raise ValueError("critical_guests must use [[critical_guests]] tables")
    if len(guests) > 200:
        raise ValueError("critical_guests is limited to 200 entries")
    for index, guest in enumerate(guests, start=1):
        if not isinstance(guest, dict) or not isinstance(guest.get("vmid"), int):
            raise ValueError(f"critical_guests entry {index} needs an integer vmid")
        reject_unknown_fields(guest, ALLOWED_FIELDS["critical_guests"], f"critical_guests entry {index}")
        require_string(guest, "name")
        require_string(guest, "backup_reference")
        require_bool(guest, "restore_drill_completed")
    return manifest


def audit(manifest: dict[str, Any]) -> list[Finding]:
    datastore = manifest["datastore"]
    encryption = manifest["encryption"]
    findings: list[Finding] = []

    if manifest["pbs_is_vm_on_protected_pve"]:
        same_host = manifest["bootstrap_host"].casefold() == manifest["pve_host"].casefold()
        if manifest["bootstrap_host_independent"] and not same_host:
            findings.append(Finding("PASS", "PBS bootstrap host", "PBS is declared as a VM on the protected PVE host, with a separate bootstrap host named.", "Keep that host bootable without the failed PVE system."))
        else:
            findings.append(Finding("BLOCKER", "PBS bootstrap host", "PBS is a VM on the protected PVE host, but no independent bootstrap host is declared.", "Identify an alternate PVE host or bare-metal PBS recovery target."))
    else:
        findings.append(Finding("PASS", "PBS bootstrap host", "PBS is declared independent of the protected PVE host.", "Confirm that it remains reachable during a PVE outage."))

    for key, label in (("independent_of_pve", "Datastore location"), ("accessible_without_pve", "Datastore access")):
        if datastore[key]:
            findings.append(Finding("PASS", label, f"Datastore {datastore['name']} is declared available without {manifest['pve_host']}.", "Recheck the NAS path and mount method during a cold-start drill."))
        else:
            findings.append(Finding("BLOCKER", label, f"Datastore {datastore['name']} depends on the protected PVE host or is not reachable without it.", "Move or expose a copy through infrastructure that survives the PVE outage."))

    if manifest["pve_config_backup_off_host"]:
        findings.append(Finding("PASS", "PVE configuration", "PVE configuration is declared backed up off-host.", "Verify the copy includes guest definitions, storage mappings, and network settings."))
    else:
        findings.append(Finding("BLOCKER", "PVE configuration", "No off-host PVE configuration backup is declared.", "Back up and rehearse recovery of PVE configuration independently of the PVE boot disk."))

    if manifest["pbs_config_backup_off_host"]:
        findings.append(Finding("PASS", "PBS configuration", "PBS configuration is declared backed up off-host.", "Keep a copy of datastore definitions and network/mount details with the runbook."))
    else:
        findings.append(Finding("WARN", "PBS configuration", "No off-host PBS configuration backup is declared.", "Record PBS datastore name, mount path, and relevant configuration outside PBS."))

    if datastore["fresh_instance_reuse_tested"]:
        findings.append(Finding("PASS", "Fresh PBS datastore reuse", "A fresh-instance reuse test is declared complete.", "Record the test date and ensure the old PBS instance was offline during reuse."))
    else:
        findings.append(Finding("WARN", "Fresh PBS datastore reuse", "Reusing the existing datastore on a fresh PBS instance has not been declared tested.", "Rehearse with the original PBS instance stopped; PBS does not support concurrent operation on the same datastore."))

    if encryption["client_side_encryption"]:
        if encryption["key_available_without_pve"] and encryption["key_available_without_pbs"]:
            findings.append(Finding("PASS", "Encryption key custody", "Encrypted backups are declared to have an independent key reference.", "Test key retrieval from a device that does not depend on PVE or PBS; never store the key in this manifest."))
        else:
            findings.append(Finding("BLOCKER", "Encryption key custody", "The encrypted-backup key is not declared available independently of both PVE and PBS.", "Move key custody to a separate, recoverable channel and test retrieval."))
    else:
        findings.append(Finding("PASS", "Encryption key custody", "Client-side encryption is declared disabled.", "Confirm that this matches the actual backup configuration."))

    if manifest["pbs_is_vm_on_protected_pve"] and manifest["pbs_vm_backup_in_datastore"]:
        findings.append(Finding("PASS", "PBS VM backup", "A PBS VM backup is declared in the external datastore.", "This backup is useful after a fresh PBS instance can read the datastore."))
    elif manifest["pbs_is_vm_on_protected_pve"]:
        findings.append(Finding("WARN", "PBS VM backup", "No PBS VM backup is declared in the external datastore.", "Decide whether to rebuild a temporary PBS instance or add a PBS VM backup outside the failed host."))

    guests = manifest.get("critical_guests", [])
    if not guests:
        findings.append(Finding("WARN", "Critical guest inventory", "No critical guests are listed.", "List the first guests to restore, their backup references, and the last successful restore drill."))
    else:
        untested = [guest["name"] for guest in guests if not guest["restore_drill_completed"]]
        if untested:
            findings.append(Finding("WARN", "Critical guest restore drills", f"Restore drills are not declared complete for: {', '.join(untested)}.", "Restore each critical guest to an isolated target and verify the service, not just the backup job."))
        else:
            findings.append(Finding("PASS", "Critical guest restore drills", f"Restore drills are declared complete for all {len(guests)} listed critical guests.", "Keep evidence and test dates with the runbook."))
    return findings


def render_plan(manifest: dict[str, Any], findings: list[Finding]) -> str:
    datastore = manifest["datastore"]
    encryption = manifest["encryption"]
    lines = [
        f"# PBS cold-start recovery checklist — {manifest['system_name']}",
        "",
        "> Generated from declared configuration. This is a plan, not proof that a backup or restore works. Review commands and paths before use. It contains no credentials or encryption-key contents.",
        "",
        "## Declared recovery layout",
        "",
        f"- PVE: `{manifest['pve_host']}`",
        f"- PBS: `{manifest['pbs_host']}` (VM on protected PVE: {manifest['pbs_is_vm_on_protected_pve']}, VMID: {manifest['pbs_vm_id']})",
        f"- Bootstrap host: `{manifest['bootstrap_host']}` (independent: {manifest['bootstrap_host_independent']})",
        f"- Datastore: `{datastore['name']}` at `{datastore['mount_path']}`",
        f"- PVE config backup off-host: {manifest['pve_config_backup_off_host']}",
        f"- PBS config backup off-host: {manifest['pbs_config_backup_off_host']}",
        f"- Client-side encryption: {encryption['client_side_encryption']}",
    ]
    if encryption["client_side_encryption"]:
        lines.append("- Encryption key custody: an out-of-band reference is declared (details intentionally omitted)")
    lines += ["", "## Audit findings", "", "| Level | Check | Finding |", "|---|---|---|"]
    for finding in findings:
        lines.append(f"| {finding.level} | {finding.check} | {finding.detail} |")
    lines += [
        "",
        "## Recovery sequence",
        "",
        # ORIGINAL (preserved, not deleted — disabled by comment): "1. Confirm the failed PVE/PBS instance is stopped before bringing the same datastore online elsewhere. Do not allow two PBS instances to operate on one datastore concurrently.",
        "1. Before recovery uses the datastore, stop the original PBS instance and follow the current instructions for that datastore backend; this checklist does not establish whether a particular multi-instance setup is safe.",
        f"2. Boot the independent recovery target `{manifest['bootstrap_host']}` and install a compatible PBS/PVE environment using the official installation instructions.",
        # ORIGINAL (preserved, not deleted — disabled by comment): f"3. Restore network access to the NAS, then mount the datastore at `{datastore['mount_path']}`. Obtain NAS authentication through its separate approved credential channel; do not add it to this file.",
        f"3. Restore network access to the NAS, then mount the datastore at `{datastore['mount_path']}`. Confirm the backing filesystem and NAS export support PBS requirements, including Unix filesystem semantics and at least 65,538 subdirectories per directory. Obtain NAS authentication through its separate approved credential channel; do not add it to this file.",
        # ORIGINAL (preserved, not deleted — disabled by comment):
        # f"4. Only after confirming the previous PBS instance is stopped, review and run this command on the fresh PBS host: `proxmox-backup-manager datastore create {shlex.quote(datastore['name'])} {shlex.quote(datastore['mount_path'])} --reuse-datastore true --overwrite-in-use true`. This can change datastore state; check the current [PBS datastore reuse instructions](https://pbs.proxmox.com/docs/storage.html) first.",
        f"4. Only after confirming the previous PBS instance is stopped, review the datastore reuse steps for its backend in the [PBS documentation](https://pbs.proxmox.com/docs/storage.html). For a filesystem datastore, the command form is `proxmox-backup-manager datastore create {shlex.quote(datastore['name'])} {shlex.quote(datastore['mount_path'])} --reuse-datastore true`. Do not add backend-specific options unless the docs for that datastore type require them. This can change datastore state; review the command and current documentation before use.",
        "5. Sign in to the fresh PBS instance and confirm expected snapshots are visible. If client-side encryption is enabled, retrieve the key through your independent secret channel and verify access without copying it into this runbook.",
        "6. Restore the PBS VM or rebuild PBS temporarily, then restore the critical guests below to an isolated target. Confirm each application starts and its data is current.",
        "7. Rebuild the original PVE host, restore its off-host configuration, reconnect storage, and record actual recovery time and any missing dependencies.",
        "",
        "## Critical guests",
        "",
    ]
    guests = manifest.get("critical_guests", [])
    if guests:
        lines += ["| VMID | Name | Backup reference | Restore drill declared |", "|---:|---|---|---|"]
        for guest in guests:
            lines.append(f"| {guest['vmid']} | {guest['name']} | {guest['backup_reference']} | {guest['restore_drill_completed']} |")
    else:
        lines.append("No critical guests were listed in the manifest.")
    lines += ["", "## Actions to resolve", ""]
    for finding in findings:
        if finding.level in {"BLOCKER", "WARN"}:
            lines.append(f"- **{finding.level} — {finding.check}:** {finding.action}")
    lines += ["", "## Verification log", "", "- Date and operator:", "- Fresh PBS instance used:", "- Datastore reuse result:", "- Guest restored and service-level checks:", "- Measured recovery time:", "- Follow-up gaps:", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit PBS cold-start dependencies and generate a recovery runbook.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("audit", "plan"):
        command = subparsers.add_parser(name)
        command.add_argument("manifest", type=Path)
        command.add_argument("--output", type=Path, help="Write output to this file instead of stdout")
        if name == "audit":
            command.add_argument("--json", action="store_true", help="Print findings as JSON")
    args = parser.parse_args()

    try:
        manifest = load_manifest(args.manifest)
        findings = audit(manifest)
        if args.command == "plan":
            output = render_plan(manifest, findings)
        elif args.json:
            output = json.dumps({"findings": [asdict(item) for item in findings]}, indent=2)
        else:
            output = "\n".join(f"{item.level:7} {item.check}: {item.detail}\n        Action: {item.action}" for item in findings)
            blockers = sum(item.level == "BLOCKER" for item in findings)
            warnings = sum(item.level == "WARN" for item in findings)
            output += f"\n\n{blockers} blocker(s), {warnings} warning(s). Findings reflect the manifest, not live system verification."
        if args.output:
            source_path = args.manifest.resolve()
            output_path = args.output.resolve()
            if source_path == output_path:
                raise ValueError("output path must not overwrite the input manifest")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            temporary_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", dir=args.output.parent,
                    prefix=f".{args.output.name}.", delete=False,
                ) as destination:
                    temporary_path = Path(destination.name)
                    destination.write(output + "\n")
                    destination.flush()
                    os.fsync(destination.fileno())
                temporary_path.replace(args.output)
            finally:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)
            # ORIGINAL (preserved, not deleted — disabled by comment): args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        return 1 if any(item.level == "BLOCKER" for item in findings) else 0
    except (ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
