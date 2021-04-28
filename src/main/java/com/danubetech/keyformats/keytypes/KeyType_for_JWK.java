package com.danubetech.keyformats.keytypes;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.OctetKeyPair;

public class KeyType_for_JWK {

	public static String keyType_for_JWK(JWK jsonWebKey) {

		if (KeyType.RSA.equals(jsonWebKey.getKeyType()))
			return jsonWebKey.getKeyType().getValue();	// "RSA"
		else if (KeyType.EC.equals(jsonWebKey.getKeyType()))
			return ((ECKey) jsonWebKey).getCurve().getName();	// "secp256k1", "BLS12381_G1", "BLS12381_G2"
		else if (KeyType.OKP.equals(jsonWebKey.getKeyType()))
			return ((OctetKeyPair) jsonWebKey).getCurve().getName();	// "Ed25519", "X25519"
		else
			throw new IllegalArgumentException("Unsupported key type " + jsonWebKey.getKeyType());
	}
}
