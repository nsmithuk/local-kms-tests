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

ASYMMETRIC_KEY_ALIASES = [
    "alias/seed_ecc_nist_p256_sign_verify",
]

SEED_ALIAS_SYMMETRIC_ENCRYPT_DECRYPT = "alias/seed_symmetric_default_encrypt_decrypt"
SEED_ALIAS_RSA_2048_ENCRYPT_DECRYPT = "alias/seed_rsa_2048_encrypt_decrypt"
SEED_ALIAS_RSA_3072_ENCRYPT_DECRYPT = "alias/seed_rsa_3072_encrypt_decrypt"
SEED_ALIAS_RSA_4096_ENCRYPT_DECRYPT = "alias/seed_rsa_4096_encrypt_decrypt"
SEED_ALIAS_RSA_2048_SIGN_VERIFY = "alias/seed_rsa_2048_sign_verify"
SEED_ALIAS_RSA_3072_SIGN_VERIFY = "alias/seed_rsa_3072_sign_verify"
SEED_ALIAS_RSA_4096_SIGN_VERIFY = "alias/seed_rsa_4096_sign_verify"
SEED_ALIAS_ECC_NIST_P256_SIGN_VERIFY = "alias/seed_ecc_nist_p256_sign_verify"
SEED_ALIAS_ECC_NIST_P384_SIGN_VERIFY = "alias/seed_ecc_nist_p384_sign_verify"
SEED_ALIAS_ECC_NIST_P521_SIGN_VERIFY = "alias/seed_ecc_nist_p521_sign_verify"
SEED_ALIAS_ECC_SECG_P256K1_SIGN_VERIFY = "alias/seed_ecc_secg_p256k1_sign_verify"
SEED_ALIAS_ECC_EDWARDS25519_SIGN_VERIFY = "alias/seed_ecc_nist_edwards25519_sign_verify"
SEED_ALIAS_ML_DSA_44_SIGN_VERIFY = "alias/seed_ml_dsa_44_sign_verify"
SEED_ALIAS_ML_DSA_65_SIGN_VERIFY = "alias/seed_ml_dsa_65_sign_verify"
SEED_ALIAS_ML_DSA_87_SIGN_VERIFY = "alias/seed_ml_dsa_87_sign_verify"
SEED_ALIAS_HMAC_224 = "alias/seed_hmac_224_generate_verify_mac"
SEED_ALIAS_HMAC_256 = "alias/seed_hmac_256_generate_verify_mac"
SEED_ALIAS_HMAC_384 = "alias/seed_hmac_384_generate_verify_mac"
SEED_ALIAS_HMAC_512 = "alias/seed_hmac_512_generate_verify_mac"
