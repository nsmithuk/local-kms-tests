import pytest
from tests.generic import ALLOWED_KEY_USAGE_BY_SPEC
# Reuse your ALLOWED_KEY_USAGE_BY_SPEC from above

ALL_VALID_KEY_USAGE_ENUMS = {
    "ENCRYPT_DECRYPT",
    "SIGN_VERIFY",
    "GENERATE_VERIFY_MAC",
    "KEY_AGREEMENT",
}

# --- Missing KeyUsage cases (should fail for all except SYMMETRIC_DEFAULT) ---

MISSING_KEY_USAGE_CASES = [
    pytest.param(key_spec, id=f"{key_spec}-missing-keyusage")
    for key_spec in ALLOWED_KEY_USAGE_BY_SPEC.keys()
    if key_spec != "SYMMETRIC_DEFAULT"
]

# --- Invalid KeyUsage cases (present but must fail) ---

INVALID_KEY_USAGE_CASES = []

for key_spec, allowed_usages in ALLOWED_KEY_USAGE_BY_SPEC.items():
    allowed_set = set(allowed_usages)

    # 1) Wrong-but-valid-enum usages for that KeySpec
    for bad_usage in sorted(ALL_VALID_KEY_USAGE_ENUMS - allowed_set):
        INVALID_KEY_USAGE_CASES.append(
            pytest.param(
                key_spec,
                bad_usage,
                id=f"{key_spec}-invalid-{bad_usage.lower()}",
            )
        )

    # 2) Not-even-a-valid-enum usage strings (always invalid)
    for bad_usage in ["", "INVALID", "encrypt_decrypt", "SIGN", "MAC", "KEY-AGREEMENT"]:
        INVALID_KEY_USAGE_CASES.append(
            pytest.param(
                key_spec,
                bad_usage,
                id=f"{key_spec}-nonsense-{bad_usage or 'empty'}",
            )
        )

# --- Tests ---

@pytest.mark.parametrize("key_spec", MISSING_KEY_USAGE_CASES)
def test_create_key_missing_key_usage_should_fail(kms_client, key_spec):
    # if key_spec == "SYMMETRIC_DEFAULT":
    #     pytest.skip("SYMMETRIC_DEFAULT has a default so should work without KeyUsage")

    code, content = kms_client.post(
        "CreateKey",
        {
            "KeySpec": key_spec,
            # KeyUsage omitted intentionally
        },
    )

    assert code != 200, f"Expected failure when KeyUsage missing for {key_spec}, got {code} {content}"


@pytest.mark.parametrize("key_spec,key_usage", INVALID_KEY_USAGE_CASES)
def test_create_key_invalid_key_usage_should_fail(kms_client, key_spec, key_usage):
    if key_spec == "SYMMETRIC_DEFAULT" and key_usage == "":
        pytest.skip("SYMMETRIC_DEFAULT has a default so should work without KeyUsage")

    code, content = kms_client.post(
        "CreateKey",
        {
            "KeySpec": key_spec,
            "KeyUsage": key_usage,
        },
    )
    assert code != 200, f"Expected failure for {key_spec} + {key_usage}, got {code} {content}"
