package com.danubetech.keyformats.crypto;

import com.danubetech.keyformats.crypto.impl.*;
import com.danubetech.keyformats.jose.JWSAlgorithms;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import org.bitcoinj.core.ECKey;

import java.security.interfaces.RSAPrivateKey;

public class PrivateKeySignerFactory {

    public static PrivateKeySigner<?> privateKeySignerForKey(KeyTypeName keyTypeName, String algorithm, Object privateKey) throws JOSEException {

        if (keyTypeName == null) throw new NullPointerException("No key type name provided.");
        if (algorithm == null) throw new NullPointerException("No algorithm provided.");
        if (privateKey == null) throw new NullPointerException("No private key provided.");

        if (KeyTypeName.RSA.equals(keyTypeName)) {

            if (JWSAlgorithm.RS256.getName().equals(algorithm)) return new RSA_RS256_PrivateKeySigner((RSAPrivateKey) privateKey);
            if (JWSAlgorithm.PS256.getName().equals(algorithm)) return new RSA_PS256_PrivateKeySigner((RSAPrivateKey) privateKey);
        } else if (KeyTypeName.secp256k1.equals(keyTypeName)) {

            if (JWSAlgorithm.ES256K.getName().equals(algorithm)) return new secp256k1_ES256K_PrivateKeySigner((ECKey) privateKey);
        } else if (KeyTypeName.BLS12381_G1.equals(keyTypeName)) {

            if (JWSAlgorithms.BBSPlus.getName().equals(algorithm)) return new BLS12381_G1_BBSPlus_PrivateKeySigner((ECKey) privateKey);
        } else if (KeyTypeName.BLS12381_G2.equals(keyTypeName)) {

            if (JWSAlgorithms.BBSPlus.getName().equals(algorithm)) return new BLS12381_G2_BBSPlus_PrivateKeySigner((ECKey) privateKey);
        } else if (KeyTypeName.Ed25519.equals(keyTypeName)) {

            if (JWSAlgorithm.EdDSA.getName().equals(algorithm)) return new Ed25519_EdDSA_PrivateKeySigner((byte[]) privateKey);
        }

        throw new IllegalArgumentException("Unsupported private key " + keyTypeName + " and/or algorithm " + algorithm);
    }
}
