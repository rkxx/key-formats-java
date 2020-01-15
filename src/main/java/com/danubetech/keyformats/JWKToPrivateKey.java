package com.danubetech.keyformats;

import java.security.interfaces.RSAPrivateKey;

import org.bitcoinj.core.ECKey;

import com.danubetech.keytypes.JWKKeyTypes;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.RSAKeyUtils;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;

public class JWKToPrivateKey {

	public static Object JWKToAnyPrivateKey(JWK jsonWebKey) throws JOSEException {

		String keyType = JWKKeyTypes.keyTypeForJWK(jsonWebKey);

		if (KeyType.RSA.getValue().equals(keyType))
			return JWKToRSAPrivateKey(jsonWebKey);
		else if (Curve.P_256K.getName().equals(keyType))
			return JWKToP_256KPrivateKey(jsonWebKey);
		else if (Curve.Ed25519.getName().equals(keyType))
			return JWKToEd25519PrivateKeyBytes(jsonWebKey);
		else if (Curve.X25519.getName().equals(keyType))
			return JWKToX25519PrivateKeyBytes(jsonWebKey);
		else
			throw new IllegalArgumentException("Unsupported key type: " + keyType);
	}

	public static RSAPrivateKey JWKToRSAPrivateKey(JWK jsonWebKey) throws JOSEException {

		if (! KeyType.RSA.equals(jsonWebKey.getKeyType())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKeyType());

		return (RSAPrivateKey) RSAKeyUtils.toRSAPrivateKey((RSAKey) jsonWebKey);
	}

	public static ECKey JWKToP_256KPrivateKey(JWK jsonWebKey) throws JOSEException {

		byte[] privateKeyBytes = JWKToP_256KPrivateKeyBytes(jsonWebKey);

		return ECKey.fromPrivate(privateKeyBytes);
	}

	public static byte[] JWKToP_256KPrivateKeyBytes(JWK jsonWebKey) throws JOSEException {

		if (! KeyType.EC.equals(jsonWebKey.getKeyType())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKeyType());

		com.nimbusds.jose.jwk.ECKey ecKey = (com.nimbusds.jose.jwk.ECKey) jsonWebKey;
		if (! Curve.P_256K.equals(ecKey.getCurve())) throw new IllegalArgumentException("Incorrect curve: " + ecKey.getCurve());

		return ecKey.getD().decode();
	}

	public static byte[] JWKToEd25519PrivateKeyBytes(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKeyType())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKeyType());

		com.nimbusds.jose.jwk.OctetKeyPair octetKeyPair = (com.nimbusds.jose.jwk.OctetKeyPair) jsonWebKey;
		if (! Curve.Ed25519.equals(octetKeyPair.getCurve())) throw new IllegalArgumentException("Incorrect curve: " + octetKeyPair.getCurve());

		byte[] privateKeyBytes = new byte[64];
		System.arraycopy(octetKeyPair.getD().decode(), 0, privateKeyBytes, 0, 32);
		System.arraycopy(octetKeyPair.getX().decode(), 0, privateKeyBytes, 32, 32);

		return privateKeyBytes;
	}

	public static byte[] JWKToX25519PrivateKeyBytes(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKeyType())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKeyType());

		com.nimbusds.jose.jwk.OctetKeyPair octetKeyPair = (com.nimbusds.jose.jwk.OctetKeyPair) jsonWebKey;
		if (! Curve.X25519.equals(octetKeyPair.getCurve())) throw new IllegalArgumentException("Incorrect curve: " + octetKeyPair.getCurve());

		byte[] privateKeyBytes = new byte[64];
		System.arraycopy(octetKeyPair.getD().decode(), 0, privateKeyBytes, 0, 32);
		System.arraycopy(octetKeyPair.getX().decode(), 0, privateKeyBytes, 32, 32);

		return privateKeyBytes;
	}
}
