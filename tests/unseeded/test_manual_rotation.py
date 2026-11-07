import os
from base64 import b64decode, b64encode
import time
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

def _list_key_rotations(kms_client, key_id: str) -> list[dict]:
    code, content = kms_client.post("ListKeyRotations", {"KeyId": key_id})
    assert code == 200
    assert isinstance(content, dict)
    assert content.get("Rotations") is not None
    assert isinstance(content["Rotations"], list)
    return content["Rotations"]


def _current_material_id_from_rotations(rotations: list[dict]) -> str | None:
    """
    Best-effort helper:
    - If your API includes an explicit flag/field for 'current', use it.
    - Otherwise, treat the newest rotation record as current.
    """
    if not rotations:
        return None

    # Prefer explicit marker if present.
    for r in rotations:
        if r.get("KeyMaterialState") == "CURRENT" and r.get("KeyMaterialId") is not None:
            return r["KeyMaterialId"]

    # Fallback: newest record (assumes list is already newest-first; if not, adjust below)
    kmid = rotations[0].get("KeyMaterialId")
    if kmid is not None:
        return kmid

    # Last resort: scan for first material id
    for r in rotations:
        if r.get("KeyMaterialId") is not None:
            return r["KeyMaterialId"]
    return None


def _describe_key(kms_client, key_id: str) -> dict:
    code, content = kms_client.post("DescribeKey", {"KeyId": key_id})
    assert code == 200
    assert isinstance(content, dict)
    assert content.get("KeyMetadata") is not None
    return content["KeyMetadata"]


def _import_key_material(
    kms_client,
    key_id: str,
    *,
    wrapping_key_spec: str = "RSA_2048",
    wrapping_algorithm: str = "RSAES_OAEP_SHA_256",
    expiration_model: str = "KEY_MATERIAL_DOES_NOT_EXPIRE",
) -> None:
    # Get params for import
    code, content = kms_client.post(
        "GetParametersForImport",
        {
            "KeyId": key_id,
            "WrappingKeySpec": wrapping_key_spec,
            "WrappingAlgorithm": wrapping_algorithm,
        },
    )
    assert code == 200
    assert isinstance(content, dict)
    assert content.get("PublicKey") is not None
    assert content.get("ImportToken") is not None

    public_key_der = b64decode(content["PublicKey"])
    import_token = content["ImportToken"]  # keep b64 for the API call

    # Generate plaintext key material (256-bit)
    plaintext_material = os.urandom(32)

    # Wrap/encrypt key material with RSA public key (OAEP SHA-256)
    pub = load_der_public_key(public_key_der)
    encrypted_material = pub.encrypt(
        plaintext_material,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Import
    code, content = kms_client.post(
        "ImportKeyMaterial",
        {
            "KeyId": key_id,
            "EncryptedKeyMaterial": b64encode(encrypted_material).decode("ascii"),
            "ImportToken": import_token,
            "ExpirationModel": expiration_model,
            "ImportType": "NEW_KEY_MATERIAL",
        },
    )
    assert code == 200
    assert isinstance(content, dict)


def test_rotate_key_on_demand_hits_limit_10(kms_client) -> None:
    # Create a normal KMS key
    code, content = kms_client.post(
        "CreateKey",
        {
            "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
        },
    )
    assert code == 200
    assert isinstance(content, dict)
    assert content.get("KeyMetadata") is not None

    key_id = content["KeyMetadata"]["KeyId"]

    md0 = _describe_key(kms_client, key_id)
    initial_material_id = md0.get("CurrentKeyMaterialId")

    # You can manually rotate at most 10 times. First 10 succeed.
    last_material_id = initial_material_id
    for i in range(10):
        if kms_client.is_real_kms():
            # KMS is quite slow rotating keys, so we need to move slowly.
            time.sleep(65)

        code, resp = kms_client.post("RotateKeyOnDemand", {"KeyId": key_id})
        assert code == 200
        assert isinstance(resp, dict)

        new_id_seen = False
        new_material_id = None
        for j in range(10):
            if kms_client.is_real_kms():
                time.sleep(3)

            rotations = _list_key_rotations(kms_client, key_id)
            new_material_id = _current_material_id_from_rotations(rotations)
            if new_material_id is None:
                continue

            new_id_seen = new_material_id != last_material_id
            if new_id_seen:
                break

        assert new_id_seen is True
        last_material_id = new_material_id

    # 11th rotation should fail
    code, resp = kms_client.post("RotateKeyOnDemand", {"KeyId": key_id})
    assert code != 200
    assert isinstance(resp, dict)
    assert resp.get("__type") is not None
    assert resp["__type"] == "LimitExceededException"


def test_external_import_two_materials_second_not_current_until_rotate(kms_client) -> None:
    # Create an EXTERNAL-origin symmetric key
    code, content = kms_client.post(
        "CreateKey",
        {
            "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "Origin": "EXTERNAL",
        },
    )
    assert code == 200
    assert isinstance(content, dict)
    assert content.get("KeyMetadata") is not None

    key_id = content["KeyMetadata"]["KeyId"]

    # Import #1
    _import_key_material(kms_client, key_id)
    md_after_1 = _describe_key(kms_client, key_id)
    current_1 = md_after_1.get("CurrentKeyMaterialId")
    assert current_1 is not None

    if kms_client.is_real_kms():
        # KMS is quite slow rotating keys, so we need to move slowly.
        time.sleep(65)

    # Import #2 (should NOT become current yet)
    _import_key_material(kms_client, key_id)
    md_after_2 = _describe_key(kms_client, key_id)
    current_2_before_rotate = md_after_2.get("CurrentKeyMaterialId")
    assert current_2_before_rotate == current_1

    # Now rotate on-demand: the second imported material should become current
    code, resp = kms_client.post("RotateKeyOnDemand", {"KeyId": key_id})
    assert code == 200
    assert isinstance(resp, dict)

    if kms_client.is_real_kms():
        # KMS is quite slow rotating keys, so we need to move slowly.
        time.sleep(65)

    md_after_rotate = _describe_key(kms_client, key_id)
    current_after_rotate = md_after_rotate.get("CurrentKeyMaterialId")
    assert current_after_rotate is not None
    assert current_after_rotate != current_1
