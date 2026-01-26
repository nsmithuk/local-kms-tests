from __future__ import annotations

import os
import time
from base64 import b64decode, b64encode
from dataclasses import dataclass
from typing import Callable, Literal, Optional

import pytest
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding


WrappingAlgorithm = Literal[
    "RSAES_OAEP_SHA_1",
    "RSAES_OAEP_SHA_256",
    "RSA_AES_KEY_WRAP_SHA_1",
    "RSA_AES_KEY_WRAP_SHA_256",
]
WrappingKeySpec = Literal["RSA_2048", "RSA_3072", "RSA_4096"]
KeyUsage = Literal["ENCRYPT_DECRYPT", "SIGN_VERIFY", "GENERATE_VERIFY_MAC"]

KeySpec = Literal[
    "SYMMETRIC_DEFAULT",
    "RSA_2048",
    "RSA_3072",
    "RSA_4096",
    "ECC_NIST_P256",
    "ECC_NIST_P384",
    "ECC_NIST_P521",
    "ECC_SECG_P256K1",
    "ECC_NIST_EDWARDS25519",
    "HMAC_224",
    "HMAC_256",
    "HMAC_384",
    "HMAC_512",
]

ImportType = Literal["NEW_KEY_MATERIAL", "EXISTING_KEY_MATERIAL"]


# --------------------------------------------------------------------------------------
# AWS behaviour helpers
# --------------------------------------------------------------------------------------


def _is_pending_import_error(content: object) -> bool:
    """
    AWS KMS returns:
      {"__type":"KMSInvalidStateException","message":"... is pending import."}
    """
    if not isinstance(content, dict):
        return False
    t = content.get("__type", "")
    msg = content.get("message", "")
    return isinstance(t, str) and "KMSInvalidStateException" in t and isinstance(msg, str) and "pending import" in msg.lower()


def _retry_post(
    kms_client,
    op: str,
    payload: dict,
    *,
    retries: int = 15,
    sleep_s: float = 0.3,
) -> tuple[int, dict]:
    """
    KMS can briefly return 'pending import' immediately after ImportKeyMaterial.
    Retry only on that transient state.
    """
    last: tuple[int, dict] | None = None
    for _ in range(retries):
        code, content = kms_client.post(op, payload)
        assert isinstance(content, dict)
        last = (code, content)
        if code == 200:
            return code, content
        if _is_pending_import_error(content):
            time.sleep(sleep_s)
            continue
        return code, content
    assert last is not None
    return last


# --------------------------------------------------------------------------------------
# Wrapping helpers
# --------------------------------------------------------------------------------------


def _hash_for_wrapping_algorithm(wrapping_algorithm: WrappingAlgorithm):
    if wrapping_algorithm in ("RSAES_OAEP_SHA_1", "RSA_AES_KEY_WRAP_SHA_1"):
        return hashes.SHA1()
    if wrapping_algorithm in ("RSAES_OAEP_SHA_256", "RSA_AES_KEY_WRAP_SHA_256"):
        return hashes.SHA256()
    raise ValueError(f"Unknown wrapping algorithm: {wrapping_algorithm}")


def _oaep_padding_for_wrapping_algorithm(wrapping_algorithm: WrappingAlgorithm) -> padding.OAEP:
    h = _hash_for_wrapping_algorithm(wrapping_algorithm)
    return padding.OAEP(mgf=padding.MGF1(algorithm=h), algorithm=h, label=None)


def _wrap_key_material(
    *,
    wrapping_pubkey_der: bytes,
    wrapping_algorithm: WrappingAlgorithm,
    plaintext_key_material: bytes,
) -> bytes:
    """
    Implements the two wrapping modes used by KMS ImportKeyMaterial:

    - RSAES_OAEP_*:
        EncryptedKeyMaterial = RSA_OAEP(plaintext_key_material)

    - RSA_AES_KEY_WRAP_*:
        aes_kek = random(32)
        wrapped_material = AES-KWP(aes_kek, plaintext_key_material)  (RFC 5649)
        encrypted_kek = RSA_OAEP(aes_kek)
        EncryptedKeyMaterial = encrypted_kek || wrapped_material
    """
    wrapping_pubkey = serialization.load_der_public_key(wrapping_pubkey_der)
    assert wrapping_pubkey is not None

    if wrapping_algorithm in ("RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256"):
        return wrapping_pubkey.encrypt(
            plaintext_key_material,
            _oaep_padding_for_wrapping_algorithm(wrapping_algorithm),
        )

    if wrapping_algorithm in ("RSA_AES_KEY_WRAP_SHA_1", "RSA_AES_KEY_WRAP_SHA_256"):
        aes_kek = os.urandom(32)  # 256-bit KEK
        wrapped_key_material = aes_key_wrap_with_padding(aes_kek, plaintext_key_material)
        encrypted_kek = wrapping_pubkey.encrypt(
            aes_kek,
            _oaep_padding_for_wrapping_algorithm(wrapping_algorithm),
        )
        return encrypted_kek + wrapped_key_material

    raise ValueError(f"Unknown wrapping algorithm: {wrapping_algorithm}")


# --------------------------------------------------------------------------------------
# KMS API helpers
# --------------------------------------------------------------------------------------


def _create_external_key(kms_client, *, key_spec: KeySpec, key_usage: KeyUsage) -> str:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": key_spec, "KeyUsage": key_usage, "Origin": "EXTERNAL"},
    )
    assert code == 200
    assert isinstance(content, dict)
    return content["KeyMetadata"]["KeyId"]


def _get_import_params(
    kms_client,
    *,
    key_id: str,
    wrapping_key_spec: WrappingKeySpec,
    wrapping_algorithm: WrappingAlgorithm,
) -> tuple[str, bytes]:
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
    return content["ImportToken"], b64decode(content["PublicKey"])


def _import_key_material(
    kms_client,
    *,
    key_id: str,
    import_token_b64: str,
    encrypted_key_material: bytes,
    expiration_model: Literal["KEY_MATERIAL_DOES_NOT_EXPIRE", "KEY_MATERIAL_EXPIRES"] = "KEY_MATERIAL_DOES_NOT_EXPIRE",
    valid_to_epoch_seconds: int | None = None,
    import_type: ImportType | None = None,
    key_material_id: str | None = None,
) -> tuple[int, dict]:
    payload: dict = {
        "KeyId": key_id,
        "ImportToken": import_token_b64,
        "EncryptedKeyMaterial": b64encode(encrypted_key_material).decode("ascii"),
        "ExpirationModel": expiration_model,
    }

    # ImportType / KeyMaterialId are only meaningful for SYMMETRIC_DEFAULT in AWS.
    if import_type is not None:
        payload["ImportType"] = import_type
    if key_material_id is not None:
        payload["KeyMaterialId"] = key_material_id

    if expiration_model == "KEY_MATERIAL_EXPIRES":
        assert valid_to_epoch_seconds is not None
        payload["ValidTo"] = valid_to_epoch_seconds  # raw HTTP JSON: epoch seconds (number)

    code, content = kms_client.post("ImportKeyMaterial", payload)
    assert isinstance(content, dict)
    return code, content


def _delete_imported_key_material(kms_client, *, key_id: str) -> None:
    code, content = kms_client.post("DeleteImportedKeyMaterial", {"KeyId": key_id})
    assert code == 200
    assert isinstance(content, dict)


# --------------------------------------------------------------------------------------
# Prove key works helpers (with retry for pending import)
# --------------------------------------------------------------------------------------


def _encrypt_decrypt_roundtrip(kms_client, *, key_id: str) -> None:
    plaintext = b"hello from import test"

    code, content = _retry_post(
        kms_client,
        "Encrypt",
        {"KeyId": key_id, "Plaintext": b64encode(plaintext).decode("ascii")},
    )
    assert code == 200
    ciphertext_b64 = content["CiphertextBlob"]

    code, content = _retry_post(
        kms_client,
        "Decrypt",
        {"CiphertextBlob": ciphertext_b64},
    )
    assert code == 200
    out_plaintext = b64decode(content["Plaintext"])
    assert out_plaintext == plaintext


def _sign_and_verify_locally(
    kms_client,
    *,
    key_id: str,
    signing_algorithm: str,
    message: bytes,
    verify_fn: Callable[[bytes, bytes], None],
) -> None:
    code, content = _retry_post(
        kms_client,
        "Sign",
        {
            "KeyId": key_id,
            "Message": b64encode(message).decode("ascii"),
            "MessageType": "RAW",
            "SigningAlgorithm": signing_algorithm,
        },
    )
    assert code == 200
    signature = b64decode(content["Signature"])
    verify_fn(signature, message)  # raises if invalid


def _generate_mac_and_verify_locally(
    kms_client,
    *,
    key_id: str,
    mac_algorithm: str,
    message: bytes,
    verify_fn: Callable[[bytes, bytes], None],
) -> None:
    code, content = _retry_post(
        kms_client,
        "GenerateMac",
        {
            "KeyId": key_id,
            "Message": b64encode(message).decode("ascii"),
            "MacAlgorithm": mac_algorithm,
        },
    )
    assert code == 200
    mac_bytes = b64decode(content["Mac"])
    verify_fn(mac_bytes, message)


# --------------------------------------------------------------------------------------
# Key material generators + local verify builders
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SignSupport:
    algorithm: str
    verify_fn: Callable[[bytes, bytes], None]


@dataclass(frozen=True)
class MacSupport:
    algorithm: str
    verify_fn: Callable[[bytes, bytes], None]


def _ecc_curve_for_key_spec(key_spec: KeySpec) -> ec.EllipticCurve:
    if key_spec == "ECC_NIST_P256":
        return ec.SECP256R1()
    if key_spec == "ECC_NIST_P384":
        return ec.SECP384R1()
    if key_spec == "ECC_NIST_P521":
        return ec.SECP521R1()
    if key_spec == "ECC_SECG_P256K1":
        return ec.SECP256K1()
    raise ValueError(f"Not an ECC curve KeySpec: {key_spec}")


def _ecc_sign_support(key_spec: KeySpec, private_key: ec.EllipticCurvePrivateKey) -> SignSupport:
    if key_spec in ("ECC_NIST_P256", "ECC_SECG_P256K1"):
        h = hashes.SHA256()
        algo = "ECDSA_SHA_256"
    elif key_spec == "ECC_NIST_P384":
        h = hashes.SHA384()
        algo = "ECDSA_SHA_384"
    elif key_spec == "ECC_NIST_P521":
        h = hashes.SHA512()
        algo = "ECDSA_SHA_512"
    else:
        raise ValueError(f"Not an ECC signing KeySpec: {key_spec}")

    pub = private_key.public_key()

    def _verify(signature: bytes, message: bytes) -> None:
        pub.verify(signature, message, ec.ECDSA(h))

    return SignSupport(algorithm=algo, verify_fn=_verify)


def _rsa_bits_for_key_spec(key_spec: KeySpec) -> int:
    if key_spec == "RSA_2048":
        return 2048
    if key_spec == "RSA_3072":
        return 3072
    if key_spec == "RSA_4096":
        return 4096
    raise ValueError(f"Not an RSA KeySpec: {key_spec}")


def _rsa_sign_support(private_key: rsa.RSAPrivateKey) -> SignSupport:
    h = hashes.SHA256()
    algo = "RSASSA_PKCS1_V1_5_SHA_256"
    pub = private_key.public_key()

    def _verify(signature: bytes, message: bytes) -> None:
        pub.verify(signature, message, padding.PKCS1v15(), h)

    return SignSupport(algorithm=algo, verify_fn=_verify)


def _ed25519_sign_support(private_key: ed25519.Ed25519PrivateKey) -> SignSupport:
    algo = "ED25519_SHA_512"
    pub = private_key.public_key()

    def _verify(signature: bytes, message: bytes) -> None:
        pub.verify(signature, message)

    return SignSupport(algorithm=algo, verify_fn=_verify)


def _hmac_support(key_spec: KeySpec, key_bytes: bytes) -> MacSupport:
    if key_spec == "HMAC_224":
        h = hashes.SHA224()
        algo = "HMAC_SHA_224"
    elif key_spec == "HMAC_256":
        h = hashes.SHA256()
        algo = "HMAC_SHA_256"
    elif key_spec == "HMAC_384":
        h = hashes.SHA384()
        algo = "HMAC_SHA_384"
    elif key_spec == "HMAC_512":
        h = hashes.SHA512()
        algo = "HMAC_SHA_512"
    else:
        raise ValueError(f"Not an HMAC KeySpec: {key_spec}")

    def _verify(mac_bytes: bytes, message: bytes) -> None:
        hm = hmac.HMAC(key_bytes, h)
        hm.update(message)
        hm.verify(mac_bytes)  # raises if invalid

    return MacSupport(algorithm=algo, verify_fn=_verify)


# --------------------------------------------------------------------------------------
# Test matrix (AWS-correct per docs)
# --------------------------------------------------------------------------------------

# Per AWS docs table:
# - Symmetric encryption key material: RSAES_OAEP_SHA_256, RSAES_OAEP_SHA_1
# - HMAC key material:              RSAES_OAEP_SHA_256, RSAES_OAEP_SHA_1
# - RSA private keys:               RSA_AES_KEY_WRAP_SHA_256, RSA_AES_KEY_WRAP_SHA_1
# - ECC private keys:               RSA_AES_KEY_WRAP_SHA_*, RSAES_OAEP_SHA_*
#   but: ECC_NIST_P521 + RSA_2048 + RSAES_OAEP_SHA_* is not supported.
# :contentReference[oaicite:3]{index=3}

SYM_WRAPPING: tuple[WrappingAlgorithm, ...] = ("RSAES_OAEP_SHA_256", "RSAES_OAEP_SHA_1")
HMAC_WRAPPING: tuple[WrappingAlgorithm, ...] = ("RSAES_OAEP_SHA_256", "RSAES_OAEP_SHA_1")
RSA_PRIV_WRAPPING: tuple[WrappingAlgorithm, ...] = ("RSA_AES_KEY_WRAP_SHA_256", "RSA_AES_KEY_WRAP_SHA_1")
ECC_PRIV_WRAPPING: tuple[WrappingAlgorithm, ...] = (
    "RSA_AES_KEY_WRAP_SHA_256",
    "RSA_AES_KEY_WRAP_SHA_1",
    "RSAES_OAEP_SHA_256",
    "RSAES_OAEP_SHA_1",
)

# Make sure we exercise RSA_2048/3072/4096 at least once overall.
# We'll keep "mostly RSA_3072" while adding a few explicit alternates.
SYM_CASES = [
    pytest.param("SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT", "RSAES_OAEP_SHA_256", "RSA_3072", id="sym_oaep_sha256_rsa3072"),
    pytest.param("SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT", "RSAES_OAEP_SHA_1", "RSA_4096", id="sym_oaep_sha1_rsa4096"),
]

ECC_SPECS: tuple[KeySpec, ...] = ("ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521", "ECC_SECG_P256K1")
ECC_CASES = []
for spec in ECC_SPECS:
    for alg in ECC_PRIV_WRAPPING:
        # Exclude unsupported: ECC_NIST_P521 + RSA_2048 + RSAES_OAEP_SHA_*
        if spec == "ECC_NIST_P521" and alg in ("RSAES_OAEP_SHA_256", "RSAES_OAEP_SHA_1"):
            # keep OAEP tests but ensure wrapping key spec is not RSA_2048
            ECC_CASES.append(pytest.param(spec, "SIGN_VERIFY", alg, "RSA_3072", id=f"{spec.lower()}_{alg.lower()}_rsa3072"))
        else:
            ECC_CASES.append(pytest.param(spec, "SIGN_VERIFY", alg, "RSA_3072", id=f"{spec.lower()}_{alg.lower()}_rsa3072"))

RSA_SPECS: tuple[KeySpec, ...] = ("RSA_2048", "RSA_3072", "RSA_4096")
RSA_CASES = [
    pytest.param("RSA_2048", "SIGN_VERIFY", "RSA_AES_KEY_WRAP_SHA_1", "RSA_3072", id="rsa_2048_aeskw_sha1_rsa3072"),
    pytest.param("RSA_3072", "SIGN_VERIFY", "RSA_AES_KEY_WRAP_SHA_256", "RSA_3072", id="rsa_3072_aeskw_sha256_rsa3072"),
    pytest.param("RSA_4096", "SIGN_VERIFY", "RSA_AES_KEY_WRAP_SHA_256", "RSA_2048", id="rsa_4096_aeskw_sha256_rsa2048"),
]

ED_CASES = [
    pytest.param("ECC_NIST_EDWARDS25519", "SIGN_VERIFY", "RSAES_OAEP_SHA_256", "RSA_3072", id="ed25519_oaep_sha256_rsa3072"),
    pytest.param("ECC_NIST_EDWARDS25519", "SIGN_VERIFY", "RSA_AES_KEY_WRAP_SHA_256", "RSA_4096", id="ed25519_aeskw_sha256_rsa4096"),
]

HMAC_SPECS: tuple[KeySpec, ...] = ("HMAC_224", "HMAC_256", "HMAC_384", "HMAC_512")
HMAC_CASES = [
    pytest.param("HMAC_224", "GENERATE_VERIFY_MAC", "RSAES_OAEP_SHA_1", "RSA_3072", id="hmac_224_oaep_sha1_rsa3072"),
    pytest.param("HMAC_256", "GENERATE_VERIFY_MAC", "RSAES_OAEP_SHA_256", "RSA_2048", id="hmac_256_oaep_sha256_rsa2048"),
    pytest.param("HMAC_384", "GENERATE_VERIFY_MAC", "RSAES_OAEP_SHA_256", "RSA_3072", id="hmac_384_oaep_sha256_rsa3072"),
    pytest.param("HMAC_512", "GENERATE_VERIFY_MAC", "RSAES_OAEP_SHA_256", "RSA_4096", id="hmac_512_oaep_sha256_rsa4096"),
]

ALL_IMPORT_CASES = SYM_CASES + ECC_CASES + RSA_CASES + ED_CASES + HMAC_CASES


# --------------------------------------------------------------------------------------
# The test
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("key_spec,key_usage,wrapping_algorithm,wrapping_key_spec", ALL_IMPORT_CASES)
def test_import_key_material_reimport_semantics(
    kms_client,
    key_spec: KeySpec,
    key_usage: KeyUsage,
    wrapping_algorithm: WrappingAlgorithm,
    wrapping_key_spec: WrappingKeySpec,
) -> None:
    # if not key_spec.startswith("HMAC"):
    #     pytest.skip("Picking specs")


    key_id = _create_external_key(kms_client, key_spec=key_spec, key_usage=key_usage)

    sign_support: Optional[SignSupport] = None
    mac_support: Optional[MacSupport] = None

    # Generate ORIGINAL plaintext key material + local verifier
    if key_spec == "SYMMETRIC_DEFAULT":
        assert wrapping_algorithm in SYM_WRAPPING
        original_plaintext = os.urandom(32)
    elif key_spec in ECC_SPECS:
        assert wrapping_algorithm in ECC_PRIV_WRAPPING
        priv = ec.generate_private_key(_ecc_curve_for_key_spec(key_spec))
        original_plaintext = priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        sign_support = _ecc_sign_support(key_spec, priv)
    elif key_spec in RSA_SPECS:
        assert wrapping_algorithm in RSA_PRIV_WRAPPING
        priv = rsa.generate_private_key(public_exponent=65537, key_size=_rsa_bits_for_key_spec(key_spec))
        original_plaintext = priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        sign_support = _rsa_sign_support(priv)
    elif key_spec == "ECC_NIST_EDWARDS25519":
        # Treat like ECC private key material category: supports RSA_AES_KEY_WRAP and RSAES_OAEP.
        assert wrapping_algorithm in ECC_PRIV_WRAPPING
        priv = ed25519.Ed25519PrivateKey.generate()
        original_plaintext = priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        sign_support = _ed25519_sign_support(priv)
    elif key_spec in HMAC_SPECS:
        assert wrapping_algorithm in HMAC_WRAPPING
        if key_spec == "HMAC_224":
            original_plaintext = os.urandom(28)
        elif key_spec == "HMAC_256":
            original_plaintext = os.urandom(32)
        elif key_spec == "HMAC_384":
            original_plaintext = os.urandom(48)
        elif key_spec == "HMAC_512":
            original_plaintext = os.urandom(64)
        else:
            raise ValueError(key_spec)
        mac_support = _hmac_support(key_spec, original_plaintext)
    else:
        raise ValueError(f"Unhandled KeySpec: {key_spec}")

    # -------------------------
    # First import
    # -------------------------
    import_token_b64, wrapping_pubkey_der = _get_import_params(
        kms_client,
        key_id=key_id,
        wrapping_key_spec=wrapping_key_spec,
        wrapping_algorithm=wrapping_algorithm,
    )
    encrypted = _wrap_key_material(
        wrapping_pubkey_der=wrapping_pubkey_der,
        wrapping_algorithm=wrapping_algorithm,
        plaintext_key_material=original_plaintext,
    )

    # For SYMMETRIC_DEFAULT: use NEW_KEY_MATERIAL for first import.
    code, content = _import_key_material(
        kms_client,
        key_id=key_id,
        import_token_b64=import_token_b64,
        encrypted_key_material=encrypted,
        expiration_model="KEY_MATERIAL_DOES_NOT_EXPIRE",
        import_type="NEW_KEY_MATERIAL" if key_spec == "SYMMETRIC_DEFAULT" else None,
    )
    assert code == 200

    key_material_id: Optional[str] = None
    if key_spec == "SYMMETRIC_DEFAULT":
        key_material_id = content.get("KeyMaterialId")
        assert isinstance(key_material_id, str) and key_material_id

    # Prove it works (handle pending import with retry)
    if key_usage == "ENCRYPT_DECRYPT":
        _encrypt_decrypt_roundtrip(kms_client, key_id=key_id)
    elif key_usage == "SIGN_VERIFY":
        assert sign_support is not None
        _sign_and_verify_locally(
            kms_client,
            key_id=key_id,
            signing_algorithm=sign_support.algorithm,
            message=b"test message",
            verify_fn=sign_support.verify_fn,
        )
    elif key_usage == "GENERATE_VERIFY_MAC":
        assert mac_support is not None
        _generate_mac_and_verify_locally(
            kms_client,
            key_id=key_id,
            mac_algorithm=mac_support.algorithm,
            message=b"test message",
            verify_fn=mac_support.verify_fn,
        )
    else:
        raise ValueError(key_usage)

    # -------------------------
    # Delete imported material
    # -------------------------
    _delete_imported_key_material(kms_client, key_id=key_id)

    # -------------------------
    # Wrong re-import (must fail)
    # -------------------------
    if key_spec in ("SYMMETRIC_DEFAULT",) or key_spec in HMAC_SPECS:
        # deterministically different but still well-formed material
        wrong_plaintext = bytes([original_plaintext[0] ^ 0x01]) + original_plaintext[1:]
    else:
        # For PKCS#8 private keys, generate a new valid key so failure is "material mismatch", not "bad ASN.1".
        if key_spec in ECC_SPECS:
            p = ec.generate_private_key(_ecc_curve_for_key_spec(key_spec))
        elif key_spec in RSA_SPECS:
            p = rsa.generate_private_key(public_exponent=65537, key_size=_rsa_bits_for_key_spec(key_spec))
        elif key_spec == "ECC_NIST_EDWARDS25519":
            p = ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError(key_spec)

        wrong_plaintext = p.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    import_token_b64, wrapping_pubkey_der = _get_import_params(
        kms_client,
        key_id=key_id,
        wrapping_key_spec=wrapping_key_spec,
        wrapping_algorithm=wrapping_algorithm,
    )
    encrypted_wrong = _wrap_key_material(
        wrapping_pubkey_der=wrapping_pubkey_der,
        wrapping_algorithm=wrapping_algorithm,
        plaintext_key_material=wrong_plaintext,
    )

    wrong_code, _ = _import_key_material(
        kms_client,
        key_id=key_id,
        import_token_b64=import_token_b64,
        encrypted_key_material=encrypted_wrong,
        expiration_model="KEY_MATERIAL_DOES_NOT_EXPIRE",
        # For SYMMETRIC_DEFAULT, force "restore" semantics
        import_type="EXISTING_KEY_MATERIAL" if key_spec == "SYMMETRIC_DEFAULT" else None,
        key_material_id=key_material_id if key_spec == "SYMMETRIC_DEFAULT" else None,
    )
    assert wrong_code != 200

    # -------------------------
    # Correct re-import (must succeed) + set expiry (< 365 days)
    # -------------------------
    now_s = int(time.time())
    valid_to_s = now_s + 30 * 24 * 60 * 60  # 30 days
    assert valid_to_s <= now_s + 365 * 24 * 60 * 60

    import_token_b64, wrapping_pubkey_der = _get_import_params(
        kms_client,
        key_id=key_id,
        wrapping_key_spec=wrapping_key_spec,
        wrapping_algorithm=wrapping_algorithm,
    )
    encrypted_original = _wrap_key_material(
        wrapping_pubkey_der=wrapping_pubkey_der,
        wrapping_algorithm=wrapping_algorithm,
        plaintext_key_material=original_plaintext,
    )

    ok_code, _ = _import_key_material(
        kms_client,
        key_id=key_id,
        import_token_b64=import_token_b64,
        encrypted_key_material=encrypted_original,
        expiration_model="KEY_MATERIAL_EXPIRES",
        valid_to_epoch_seconds=valid_to_s,
        import_type="EXISTING_KEY_MATERIAL" if key_spec == "SYMMETRIC_DEFAULT" else None,
        key_material_id=key_material_id if key_spec == "SYMMETRIC_DEFAULT" else None,
    )
    assert ok_code == 200

    # Prove it works again (handle pending import with retry)
    if key_usage == "ENCRYPT_DECRYPT":
        _encrypt_decrypt_roundtrip(kms_client, key_id=key_id)
    elif key_usage == "SIGN_VERIFY":
        assert sign_support is not None
        _sign_and_verify_locally(
            kms_client,
            key_id=key_id,
            signing_algorithm=sign_support.algorithm,
            message=b"test message 2",
            verify_fn=sign_support.verify_fn,
        )
    elif key_usage == "GENERATE_VERIFY_MAC":
        assert mac_support is not None
        _generate_mac_and_verify_locally(
            kms_client,
            key_id=key_id,
            mac_algorithm=mac_support.algorithm,
            message=b"test message 2",
            verify_fn=mac_support.verify_fn,
        )
    else:
        raise ValueError(key_usage)
