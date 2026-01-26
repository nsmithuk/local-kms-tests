
ALLOWED_KEY_USAGE_BY_SPEC = {
    # Symmetric encryption
    "SYMMETRIC_DEFAULT": ["ENCRYPT_DECRYPT"],

    # RSA
    "RSA_2048": ["ENCRYPT_DECRYPT", "SIGN_VERIFY"],
    "RSA_3072": ["ENCRYPT_DECRYPT", "SIGN_VERIFY"],
    "RSA_4096": ["ENCRYPT_DECRYPT", "SIGN_VERIFY"],

    # ECC (NIST curves): signing OR key agreement
    "ECC_NIST_P256": ["SIGN_VERIFY", "KEY_AGREEMENT"],
    "ECC_NIST_P384": ["SIGN_VERIFY", "KEY_AGREEMENT"],
    "ECC_NIST_P521": ["SIGN_VERIFY", "KEY_AGREEMENT"],

    # secp256k1: signing only
    "ECC_SECG_P256K1": ["SIGN_VERIFY"],

    # Edwards (Ed25519): signing only
    "ECC_NIST_EDWARDS25519": ["SIGN_VERIFY"],

    # HMAC: MAC only (required)
    "HMAC_224": ["GENERATE_VERIFY_MAC"],
    "HMAC_256": ["GENERATE_VERIFY_MAC"],
    "HMAC_384": ["GENERATE_VERIFY_MAC"],
    "HMAC_512": ["GENERATE_VERIFY_MAC"],

    # ML-DSA: signing only
    "ML_DSA_44": ["SIGN_VERIFY"],
    "ML_DSA_65": ["SIGN_VERIFY"],
    "ML_DSA_87": ["SIGN_VERIFY"],

    # SM2 (China Regions only) - We're not supporting this.
    # "SM2": ["ENCRYPT_DECRYPT", "SIGN_VERIFY", "KEY_AGREEMENT"],
}
