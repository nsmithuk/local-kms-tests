from base64 import b64decode
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
import pytest
from . import ASYMMETRIC_KEY_ALIASES
from cryptography.hazmat.primitives.serialization import load_der_public_key


@pytest.mark.parametrize("key_alias", ASYMMETRIC_KEY_ALIASES)
def test_get_public_key_for_all_asymmetric_seeds(kms_client, key_alias):
    code, content = kms_client.post("GetPublicKey", {"KeyId": key_alias})

    assert code == 200
    assert isinstance(content, dict)
    assert "PublicKey" in content
    assert "KeySpec" in content
    assert len(content["PublicKey"]) > 0

    pub = load_der_public_key(b64decode(content["PublicKey"]))

    key_spec = content["KeySpec"]

    if key_spec.startswith("RSA_"):
        assert isinstance(pub, rsa.RSAPublicKey)
    elif key_spec == "ECC_NIST_EDWARDS25519":
        assert isinstance(pub, ed25519.Ed25519PublicKey)
    else:
        assert isinstance(pub, ec.EllipticCurvePublicKey)
