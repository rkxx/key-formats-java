package com.danubetech.keyformats.jose;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyType;

import java.util.HashMap;
import java.util.Map;

public enum KeyTypeName {
    RSA(KeyType.RSA.getValue()),
    secp256k1(Curve.SECP256K1.getName()),
    BLS12381_G1(Curves.BLS12381_G1.getName()),
    BLS12381_G2(Curves.BLS12381_G2.getName()),
    Ed25519(Curve.Ed25519.getName()),
    X25519(Curve.X25519.getName());

    private static final Map<String, KeyTypeName> KEY_TYPE_NAME_MAP = new HashMap<>();

    private String value;

    static {
        for (KeyTypeName keyType : KeyTypeName.values()) {
            KEY_TYPE_NAME_MAP.put(keyType.getValue(), keyType);
        }
    }

    private KeyTypeName(String value) {
        this.value = value;
    }

    public String getValue() {
        return this.value;
    }

    public static KeyTypeName from(String value) {
        return KEY_TYPE_NAME_MAP.get(value);
    }
}
