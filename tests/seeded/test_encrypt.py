import hashlib

import pytest
from base64 import b64encode, b64decode
import mldsa_mu
import random
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from tests.constants import (
    SEED_ALIAS_RSA_2048_ENCRYPT_DECRYPT,
    SEED_ALIAS_RSA_3072_ENCRYPT_DECRYPT,
    SEED_ALIAS_RSA_4096_ENCRYPT_DECRYPT,
    SEED_ALIAS_SYMMETRIC_ENCRYPT_DECRYPT,
)

ENCRYPT_CASES = [
    pytest.param("SYMMETRIC_DEFAULT", "SYMMETRIC_DEFAULT", SEED_ALIAS_SYMMETRIC_ENCRYPT_DECRYPT, id="symmetric_default"),

    pytest.param("RSA_2048", "RSAES_OAEP_SHA_1", SEED_ALIAS_RSA_2048_ENCRYPT_DECRYPT, id="rsa_2048_sha1"),
    pytest.param("RSA_3072", "RSAES_OAEP_SHA_1", SEED_ALIAS_RSA_3072_ENCRYPT_DECRYPT, id="rsa_3072_sha1"),
    pytest.param("RSA_4096", "RSAES_OAEP_SHA_1", SEED_ALIAS_RSA_4096_ENCRYPT_DECRYPT, id="rsa_4096_sha1"),

    pytest.param("RSA_2048", "RSAES_OAEP_SHA_256", SEED_ALIAS_RSA_2048_ENCRYPT_DECRYPT, id="rsa_2048_sha2"),
    pytest.param("RSA_3072", "RSAES_OAEP_SHA_256", SEED_ALIAS_RSA_3072_ENCRYPT_DECRYPT, id="rsa_3072_sha2"),
    pytest.param("RSA_4096", "RSAES_OAEP_SHA_256", SEED_ALIAS_RSA_4096_ENCRYPT_DECRYPT, id="rsa_4096_sha2"),
]



@pytest.mark.parametrize("key_spec,encryption_algorithm,key_id", ENCRYPT_CASES)
def test_encrypt_decrypt(
    kms_client,
    key_spec: str,
    encryption_algorithm: str,
    key_id: str,
) -> None:

    plaintext = b"Test Message"

    code, content = kms_client.post('Encrypt',{
        'KeyId': key_id,
        'EncryptionAlgorithm': encryption_algorithm,
        'Plaintext': b64encode(plaintext).decode('ascii'),
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('CiphertextBlob', '')) > 0

    cipher_text_blob = content.get('CiphertextBlob')

    # ---

    code, content = kms_client.post('Decrypt',{
        'KeyId': key_id,
        'EncryptionAlgorithm': encryption_algorithm,
        'CiphertextBlob': cipher_text_blob,
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('Plaintext', '')) > 0

    assert b64decode(content.get('Plaintext')) == plaintext

    # -----------------------------------------------------
    # Test ReEncryption

    # TO keep it simple, we reencrypt everything to this AES key.
    re_encrypt_key_id = SEED_ALIAS_SYMMETRIC_ENCRYPT_DECRYPT

    code, content = kms_client.post('ReEncrypt',{
        'CiphertextBlob': cipher_text_blob,
        'SourceKeyId': key_id,
        'SourceEncryptionAlgorithm': encryption_algorithm,

        'DestinationKeyId': re_encrypt_key_id,
        'DestinationEncryptionAlgorithm': "SYMMETRIC_DEFAULT",
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('CiphertextBlob', '')) > 0
    code, content = kms_client.post('Decrypt',{
        'EncryptionAlgorithm': "SYMMETRIC_DEFAULT",
        'CiphertextBlob': content.get('CiphertextBlob'),
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('Plaintext', '')) > 0

    assert b64decode(content.get('Plaintext')) == plaintext
