package com.danubetech.keyformats;

import java.security.interfaces.RSAPrivateKey;

import org.bitcoinj.core.ECKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.RSAKeyUtils;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;

public class JWKToPrivateKey {

	public static RSAPrivateKey JWKToRSAPrivateKey(JWK jsonWebKey) throws JOSEException {

		if (! KeyType.RSA.equals(jsonWebKey.getKeyType())) throw new IllegalArgumentException("Incorrect key type.");

		return (RSAPrivateKey) RSAKeyUtils.toRSAPrivateKey((RSAKey) jsonWebKey);
	}

	public static ECKey JWKToP_256KPrivateKey(JWK jsonWebKey) throws JOSEException {

		byte[] privateKeyBytes = JWKToP_256KPrivateKeyBytes(jsonWebKey);

		return ECKey.fromPrivate(privateKeyBytes);
	}

	public static byte[] JWKToP_256KPrivateKeyBytes(JWK jsonWebKey) throws JOSEException {

		if (! KeyType.EC.equals(jsonWebKey.getKeyType())) throw new IllegalArgumentException("Incorrect key type.");

		com.nimbusds.jose.jwk.ECKey ecKey = (com.nimbusds.jose.jwk.ECKey) jsonWebKey;
		if (! Curve.P_256K.equals(ecKey.getCurve())) throw new IllegalArgumentException("Incorrect curve.");

		return ecKey.getD().decode();
	}

	public static byte[] JWKToEd25519PrivateKeyBytes(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKeyType())) throw new IllegalArgumentException("Incorrect key type.");

		com.nimbusds.jose.jwk.OctetKeyPair octetKeyPair = (com.nimbusds.jose.jwk.OctetKeyPair) jsonWebKey;
		if (! Curve.Ed25519.equals(octetKeyPair.getCurve())) throw new IllegalArgumentException("Incorrect curve.");

		byte[] privateKeyBytes = octetKeyPair.getD().decode();

		return privateKeyBytes;
	}

	public static byte[] JWKToX25519PrivateKeyBytes(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKeyType())) throw new IllegalArgumentException("Incorrect key type.");

		com.nimbusds.jose.jwk.OctetKeyPair octetKeyPair = (com.nimbusds.jose.jwk.OctetKeyPair) jsonWebKey;
		if (! Curve.X25519.equals(octetKeyPair.getCurve())) throw new IllegalArgumentException("Incorrect curve.");

		byte[] privateKeyBytes = octetKeyPair.getD().decode();

		return privateKeyBytes;
	}
}
