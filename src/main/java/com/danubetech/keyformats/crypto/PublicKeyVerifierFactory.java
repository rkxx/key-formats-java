package com.danubetech.keyformats.crypto;

import com.danubetech.keyformats.crypto.impl.*;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public class PublicKeyVerifierFactory {

    public static PublicKeyVerifier<?> publicKeyVerifierForKey(KeyTypeName keyTypeName, String algorithm, Object publicKey) {

        if (keyTypeName == null) throw new NullPointerException("No key type name provided.");
        if (algorithm == null) throw new NullPointerException("No algorithm provided.");
        if (publicKey == null) throw new NullPointerException("No public key provided.");

        if (KeyTypeName.RSA.equals(keyTypeName)) {

            if (JWSAlgorithm.RS256.equals(algorithm)) return new RSA_RS256_PublicKeyVerifier((RSAPublicKey) publicKey);
            if (JWSAlgorithm.PS256.equals(algorithm)) return new RSA_PS256_PublicKeyVerifier((RSAPublicKey) publicKey);
        } else if (KeyTypeName.secp256k1.equals(keyTypeName)) {

            if (JWSAlgorithm.ES256K.equals(algorithm)) return new secp256k1_ES256K_PublicKeyVerifier((ECPublicKey) publicKey);
            if (JWSAlgorithm.ES256KCC.equals(algorithm)) return new secp256k1_ES256KCC_PublicKeyVerifier((ECPublicKey) publicKey);
        } else if (KeyTypeName.Bls12381G1.equals(keyTypeName)) {

            if (JWSAlgorithm.BBSPlus.equals(algorithm)) return new Bls12381G1_BBSPlus_PublicKeyVerifier((ECPublicKey) publicKey);
        } else if (KeyTypeName.Bls12381G2.equals(keyTypeName)) {

            if (JWSAlgorithm.BBSPlus.equals(algorithm)) return new Bls12381G2_BBSPlus_PublicKeyVerifier((ECPublicKey) publicKey);
        } else if (KeyTypeName.Ed25519.equals(keyTypeName)) {

            if (JWSAlgorithm.EdDSA.equals(algorithm)) return new Ed25519_EdDSA_PublicKeyVerifier((byte[]) publicKey);
        }

        throw new IllegalArgumentException("Unsupported public key " + keyTypeName + " and/or algorithm " + algorithm);
    }
}
