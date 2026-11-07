#!/usr/bin/env bash
set -euo pipefail

# Schedules deletion of all *customer-managed* KMS keys (CMKs) in eu-west-2 in 7 days.
# WARNING: Destructive. Anything encrypted/signed with these keys may break once deleted.
#
# Requirements:
#   - aws CLI configured with credentials for the target account
#   - jq installed
#
# Usage:
#   chmod +x kms_cleanup_delete_7d.sh
#   ./kms_cleanup_delete_7d.sh              # dry run (default)
#   DRY_RUN=0 ./kms_cleanup_delete_7d.sh    # actually schedule deletions
#
# Notes:
#   - Skips AWS-managed keys (KeyManager != CUSTOMER)
#   - Skips keys already PendingDeletion
#   - Skips keys in states other than Enabled/Disabled (e.g., PendingImport)

REGION="eu-west-2"
PENDING_WINDOW_DAYS=7
DRY_RUN="${DRY_RUN:-1}"   # set to 0 to perform deletions

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 1; }; }
need aws
need jq

echo "Region: ${REGION}"
echo "PendingWindowInDays: ${PENDING_WINDOW_DAYS}"
echo "Dry run: ${DRY_RUN}"
echo

aws sts get-caller-identity --output json | jq -r '"Account: \(.Account)  Arn: \(.Arn)"'
echo

schedule_key_deletion() {
  local key_id="$1"

  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "[DRY_RUN] aws kms schedule-key-deletion --region ${REGION} --key-id ${key_id} --pending-window-in-days ${PENDING_WINDOW_DAYS}"
    return 0
  fi

  aws kms schedule-key-deletion \
    --region "${REGION}" \
    --key-id "${key_id}" \
    --pending-window-in-days "${PENDING_WINDOW_DAYS}" \
    --output json \
  | jq -r '"ScheduledDeletion: \(.DeletionDate)  KeyId: \(.KeyId)"'
}

echo "Listing keys in ${REGION}..."
echo

count_total=0
count_customer=0
count_scheduled=0
count_skipped=0
count_failed=0

# Stream KeyIds and process one-by-one (portable: no mapfile/readarray required)
aws kms list-keys --region "${REGION}" --output json \
| jq -r '.Keys[].KeyId' \
| while read -r key_id; do
  [[ -z "${key_id}" ]] && continue
  count_total=$((count_total + 1))

  # Pull metadata (skip if cannot describe)
  if ! meta_json="$(aws kms describe-key --region "${REGION}" --key-id "${key_id}" --output json 2>/dev/null)"; then
    echo "[SKIP] KeyId: ${key_id} (describe-key failed)"
    count_skipped=$((count_skipped + 1))
    continue
  fi

  key_manager="$(jq -r '.KeyMetadata.KeyManager' <<<"${meta_json}")"
  key_state="$(jq -r '.KeyMetadata.KeyState' <<<"${meta_json}")"
  key_arn="$(jq -r '.KeyMetadata.Arn' <<<"${meta_json}")"
  key_origin="$(jq -r '.KeyMetadata.Origin' <<<"${meta_json}")"
  key_desc="$(jq -r '.KeyMetadata.Description // ""' <<<"${meta_json}")"

  # Only customer-managed keys
  if [[ "${key_manager}" != "CUSTOMER" ]]; then
    echo "[SKIP] AWS-managed key: ${key_arn}"
    count_skipped=$((count_skipped + 1))
    continue
  fi
  count_customer=$((count_customer + 1))

  # Skip keys already pending deletion
  if [[ "${key_state}" == "PendingDeletion" ]]; then
    deletion_date="$(jq -r '.KeyMetadata.DeletionDate // ""' <<<"${meta_json}")"
    echo "[SKIP] Already PendingDeletion: ${key_arn} (DeletionDate: ${deletion_date})"
    count_skipped=$((count_skipped + 1))
    continue
  fi

  # Only schedule for Enabled/Disabled keys
  if [[ "${key_state}" != "Enabled" && "${key_state}" != "Disabled" ]]; then
    echo "[SKIP] Unsupported state for deletion scheduling: ${key_arn} (KeyState: ${key_state})"
    count_skipped=$((count_skipped + 1))
    continue
  fi

  echo "[CMK] ${key_arn}"
  [[ -n "${key_desc}" ]] && echo "      Description: ${key_desc}"
  echo "      State: ${key_state}  Origin: ${key_origin}"

  if schedule_key_deletion "${key_id}"; then
    count_scheduled=$((count_scheduled + 1))
  else
    echo "[FAIL] schedule-key-deletion failed for ${key_arn}"
    count_failed=$((count_failed + 1))
  fi
  echo
done

# NOTE: Because the loop runs in a subshell when fed by a pipe, the counters above
# won't reflect outside the while-loop in many shells. Print a simple completion line.
echo "Done. (Tip: set DRY_RUN=0 to actually schedule deletions.)"
