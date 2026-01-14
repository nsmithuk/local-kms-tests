from base64 import b64encode, b64decode
import hashlib
import mldsa_mu

def test_create_key_valid_combinations(kms_client):
    message = "Test Message"
    digest = hashlib.sha512(message.encode("utf-8")).digest()

    code, content = kms_client.post('Sign',{
        'KeyId': "alias/seed_ml_dsa_87",
        # 'MessageType': 'DIGEST',
        'SigningAlgorithm' : 'ML_DSA_SHAKE_256',
        'Message': b64encode(message.encode("utf-8")).decode('ascii')
        # 'Message': b64encode(digest).decode('ascii')
    })

    assert code == 200
    assert isinstance(content, dict)
    # assert 'PublicKey' in content
    # assert 'KeySpec' in content
    # assert len(content['PublicKey']) > 0
    #

    # message = "Test Message differant"

    code, content = kms_client.post('Verify',{
        'KeyId': "alias/seed_ml_dsa_87",
        # 'MessageType': 'DIGEST',
        'SigningAlgorithm' : 'ML_DSA_SHAKE_256',
        'Message': b64encode(message.encode("utf-8")).decode('ascii'),
        # 'Message': b64encode(digest).decode('ascii')
        'Signature': content['Signature'],
    })

    assert code == 200
    assert isinstance(content, dict)

def test_ml_dsa_external_mu(kms_client):
    key_id = "alias/seed_ml_dsa_87"
    # key_id = "alias/external-mu-test"
    message = "Test Message"

    # -----------------------

    code, content = kms_client.post('GetPublicKey',{
        'KeyId': key_id,
    })

    # -----------------------

    raw_public_key = mldsa_mu.public_key_from_pkix_b64(content['PublicKey'])
    mu = mldsa_mu.generate(raw_public_key, message.encode("utf-8"))


    code, content = kms_client.post('Sign',{
        'KeyId': key_id,
        'MessageType': 'RAW',
        'SigningAlgorithm' : 'ML_DSA_SHAKE_256',
        'Message': b64encode(message.encode("utf-8")).decode('ascii')
    })
    # code, content = kms_client.post('Sign',{
    #     'KeyId': key_id,
    #     'MessageType': 'EXTERNAL_MU',
    #     'SigningAlgorithm' : 'ML_DSA_SHAKE_256',
    #     'Message': b64encode(mu).decode('ascii')
    # })

    assert code == 200
    assert isinstance(content, dict)
    # assert 'PublicKey' in content
    # assert 'KeySpec' in content
    # assert len(content['PublicKey']) > 0
    #

    # message = "Test Message differant"

    # code, content = kms_client.post('Verify',{
    #     'KeyId': key_id,
    #     'MessageType': 'RAW',
    #     'SigningAlgorithm' : 'ML_DSA_SHAKE_256',
    #     'Message': b64encode(message.encode("utf-8")).decode('ascii'),
    #     'Signature': content['Signature'],
    # })
    code, content = kms_client.post('Verify',{
        'KeyId': key_id,
        'MessageType': 'EXTERNAL_MU',
        'SigningAlgorithm' : 'ML_DSA_SHAKE_256',
        'Message': b64encode(mu).decode('ascii'),
        'Signature': content['Signature'],
    })

    assert code == 200
    assert isinstance(content, dict)


# import base64
# from pyasn1.codec.der import decoder
# from pyasn1_modules import rfc5280
#
# def raw_public_key_from_pkix_b64(pkix_b64: str) -> bytes:
#     """
#     Extract the scheme public key bytes from a PKIX / SPKI DER public key.
#
#     Equivalent to:
#       base64 --decode | openssl asn1parse -inform DER -strparse ... -out -
#
#     Returns:
#         Raw public key bytes (BIT STRING contents, minus unused-bits byte)
#     """
#     spki_der = base64.b64decode(pkix_b64)
#
#     spki, _ = decoder.decode(
#         spki_der,
#         asn1Spec=rfc5280.SubjectPublicKeyInfo(),
#     )
#
#     return spki["subjectPublicKey"].asOctets()
#
#
# TR_SIZE = 64
# MU_SIZE = 64
#
# def generate_mu(raw_public_key: bytes, message: bytes, context: bytes = b"") -> bytes:
#     """
#     μ = SHAKE256( tr || M', 64 )
#
#     where:
#       tr = SHAKE256(raw_public_key, 64)
#       M' = 0x00 || len(context) || context || message
#     """
#     if len(context) > 255:
#         raise ValueError("context length must fit in one byte (0..255)")
#
#     tr = hashlib.shake_256(raw_public_key).digest(TR_SIZE)
#
#     mprime = b"\x00" + bytes([len(context)]) + context + message
#
#     return hashlib.shake_256(tr + mprime).digest(MU_SIZE)
