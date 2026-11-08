#!/usr/bin/env python3
"""
Schedule deletion of all customer-managed KMS keys in the target region.

Covers every key created by the test suite — both the seeded keys provisioned
by setup_aws_seeds.py and any keys created during test runs.

Skips:
  - AWS-managed keys (KeyManager != CUSTOMER)
  - Keys already PendingDeletion

Schedules deletion (7-day window) for keys in any other state:
  - Enabled
  - Disabled
  - PendingImport  (keys created with Origin=EXTERNAL that never received material,
                    or had their material deleted)

Usage:
    python scripts/kms_cleanup.py             # dry run (default)
    python scripts/kms_cleanup.py --execute   # actually schedule deletions
"""

import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client import KmsClient

PENDING_WINDOW_DAYS = 7
SCHEDULABLE_STATES = {"Enabled", "Disabled", "PendingImport"}


def delete_aliases_for_key(client: KmsClient, key_id: str) -> None:
    marker = None
    while True:
        payload: dict = {"KeyId": key_id, "Limit": 100}
        if marker:
            payload["Marker"] = marker
        code, content = client.post("ListAliases", payload)
        if code != 200:
            print(f"  [WARN] ListAliases failed for {key_id}: {content}")
            return
        for alias in content.get("Aliases", []):
            name = alias.get("AliasName", "")
            if not name.startswith("alias/aws/"):  # skip AWS-managed aliases
                code, _ = client.post("DeleteAlias", {"AliasName": name})
                if code != 200:
                    print(f"  [WARN] DeleteAlias {name} failed")
                else:
                    print(f"  [ALIAS] deleted {name}")
        if content.get("Truncated"):
            marker = content["NextMarker"]
        else:
            break


def list_all_key_ids(client: KmsClient) -> list[str]:
    key_ids = []
    marker = None
    while True:
        payload: dict = {"Limit": 100}
        if marker:
            payload["Marker"] = marker
        code, content = client.post("ListKeys", payload)
        if code != 200:
            print(f"[ERROR] ListKeys failed: {content}", file=sys.stderr)
            sys.exit(1)
        key_ids.extend(k["KeyId"] for k in content.get("Keys", []))
        if content.get("Truncated"):
            marker = content["NextMarker"]
        else:
            break
    return key_ids


def run(client: KmsClient, dry_run: bool) -> None:
    print(f"Listing keys... (dry_run={dry_run})\n")

    key_ids = list_all_key_ids(client)
    print(f"Found {len(key_ids)} key(s) total.\n")

    scheduled = skipped = failed = 0

    for key_id in key_ids:
        code, content = client.post("DescribeKey", {"KeyId": key_id})
        if code != 200:
            print(f"[SKIP]   {key_id} (DescribeKey failed: {content})")
            skipped += 1
            continue

        md = content["KeyMetadata"]
        key_arn   = md.get("Arn", key_id)
        manager   = md.get("KeyManager")
        state     = md.get("KeyState")
        desc      = md.get("Description") or ""

        if manager != "CUSTOMER":
            print(f"[SKIP]   {key_arn}  state={state}  (AWS-managed)")
            skipped += 1
            continue

        if state == "PendingDeletion":
            deletion_date = md.get("DeletionDate", "")
            print(f"[SKIP]   {key_arn}  (already PendingDeletion, DeletionDate={deletion_date})")
            if not dry_run:
                delete_aliases_for_key(client, key_id)
            skipped += 1
            continue

        if state not in SCHEDULABLE_STATES:
            print(f"[SKIP]   {key_arn}  state={state}  (unschedulable)")
            skipped += 1
            continue

        label = f"{key_arn}  state={state}"
        if desc:
            label += f"  desc={desc!r}"

        if dry_run:
            print(f"[DRY_RUN] {label}")
            scheduled += 1
            continue

        delete_aliases_for_key(client, key_id)

        code, content = client.post(
            "ScheduleKeyDeletion",
            {"KeyId": key_id, "PendingWindowInDays": PENDING_WINDOW_DAYS},
        )
        if code != 200:
            print(f"[FAIL]   {label}  error={content}")
            failed += 1
        else:
            print(f"[DELETE] {label}  DeletionDate={content.get('DeletionDate')}")
            scheduled += 1

    action = "would schedule" if dry_run else "scheduled"
    print(f"\nDone. {action}={scheduled}  skipped={skipped}  failed={failed}")
    if not dry_run and scheduled:
        print(f"Keys will be permanently deleted after {PENDING_WINDOW_DAYS} days.")
    if dry_run:
        print("\nRe-run with --execute to actually schedule deletions.")
    if failed:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--execute", action="store_true", help="Actually schedule deletions (default is dry run)")
    args = parser.parse_args()

    client = KmsClient(
        kms_url="",
        aws_access_key=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        aws_session_token=os.getenv("AWS_SESSION_TOKEN"),
        real_kms=True,
    )

    run(client, dry_run=not args.execute)


if __name__ == "__main__":
    main()
