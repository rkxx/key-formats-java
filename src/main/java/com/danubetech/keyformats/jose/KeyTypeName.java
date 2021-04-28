package com.danubetech.keyformats.jose;

import java.util.HashMap;
import java.util.Map;

public enum KeyTypeName {
    RSA(KeyType.RSA),
    secp256k1(Curve.secp256k1),
    BLS12381_G1(Curve.BLS12381_G1),
    BLS12381_G2(Curve.BLS12381_G2),
    Ed25519(Curve.Ed25519),
    X25519(Curve.X25519);

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
