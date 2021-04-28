package com.danubetech.keyformats;

import java.security.interfaces.RSAPrivateKey;

import com.danubetech.keyformats.jose.Curves;
import com.danubetech.keyformats.jose.KeyTypeName;
import org.bitcoinj.core.ECKey;

import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.RSAKeyUtils;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;

public class JWK_to_PrivateKey {

	public static Object JWK_to_anyPrivateKey(JWK jsonWebKey) throws JOSEException {

		KeyTypeName keyType = KeyTypeName_for_JWK.keyTypeName_for_JWK(jsonWebKey);

		if (keyType == KeyTypeName.RSA)
			return JWK_to_RSAPrivateKey(jsonWebKey);
		else if (keyType == KeyTypeName.secp256k1)
			return JWK_to_secp256k1PrivateKey(jsonWebKey);
		else if (keyType == KeyTypeName.BLS12381_G1)
			return JWK_to_BLS12381_G1PrivateKey(jsonWebKey);
		else if (keyType == KeyTypeName.BLS12381_G2)
			return JWK_to_BLS12381_G2PrivateKey(jsonWebKey);
		else if (keyType == KeyTypeName.Ed25519)
			return JWK_to_Ed25519PrivateKeyBytes(jsonWebKey);
		else if (keyType == KeyTypeName.X25519)
			return JWK_to_X25519PrivateKeyBytes(jsonWebKey);
		else
			throw new IllegalArgumentException("Unsupported key type: " + keyType);
	}

	public static RSAPrivateKey JWK_to_RSAPrivateKey(JWK jsonWebKey) throws JOSEException {

		if (! KeyType.RSA.equals(jsonWebKey.getKeyType())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKeyType());

		return (RSAPrivateKey) RSAKeyUtils.toRSAPrivateKey((RSAKey) jsonWebKey);
	}

	public static ECKey JWK_to_secp256k1PrivateKey(JWK jsonWebKey) throws JOSEException {

		byte[] privateKeyBytes = JWK_to_secp256k1PrivateKeyBytes(jsonWebKey);

		return ECKey.fromPrivate(privateKeyBytes);
	}

	public static byte[] JWK_to_secp256k1PrivateKeyBytes(JWK jsonWebKey) throws JOSEException {

		if (! KeyType.EC.equals(jsonWebKey.getKeyType())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKeyType());

		com.nimbusds.jose.jwk.ECKey ecKey = (com.nimbusds.jose.jwk.ECKey) jsonWebKey;
		if (! Curve.SECP256K1.equals(ecKey.getCurve())) throw new IllegalArgumentException("Incorrect curve: " + ecKey.getCurve());

		return ecKey.getD().decode();
	}

	public static ECKey JWK_to_BLS12381_G1PrivateKey(JWK jsonWebKey) throws JOSEException {

		byte[] privateKeyBytes = JWK_to_BLS12381_G1PrivateKeyBytes(jsonWebKey);

		return ECKey.fromPrivate(privateKeyBytes);
	}

	public static byte[] JWK_to_BLS12381_G1PrivateKeyBytes(JWK jsonWebKey) throws JOSEException {

		if (! KeyType.EC.equals(jsonWebKey.getKeyType())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKeyType());

		com.nimbusds.jose.jwk.ECKey ecKey = (com.nimbusds.jose.jwk.ECKey) jsonWebKey;
		if (! Curves.BLS12381_G1.equals(ecKey.getCurve())) throw new IllegalArgumentException("Incorrect curve: " + ecKey.getCurve());

		return ecKey.getD().decode();
	}

	public static ECKey JWK_to_BLS12381_G2PrivateKey(JWK jsonWebKey) throws JOSEException {

		byte[] privateKeyBytes = JWK_to_BLS12381_G2PrivateKeyBytes(jsonWebKey);

		return ECKey.fromPrivate(privateKeyBytes);
	}

	public static byte[] JWK_to_BLS12381_G2PrivateKeyBytes(JWK jsonWebKey) throws JOSEException {

		if (! KeyType.EC.equals(jsonWebKey.getKeyType())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKeyType());

		com.nimbusds.jose.jwk.ECKey ecKey = (com.nimbusds.jose.jwk.ECKey) jsonWebKey;
		if (! Curves.BLS12381_G2.equals(ecKey.getCurve())) throw new IllegalArgumentException("Incorrect curve: " + ecKey.getCurve());

		return ecKey.getD().decode();
	}

	public static byte[] JWK_to_Ed25519PrivateKeyBytes(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKeyType())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKeyType());

		com.nimbusds.jose.jwk.OctetKeyPair octetKeyPair = (com.nimbusds.jose.jwk.OctetKeyPair) jsonWebKey;
		if (! Curve.Ed25519.equals(octetKeyPair.getCurve())) throw new IllegalArgumentException("Incorrect curve: " + octetKeyPair.getCurve());

		byte[] privateKeyBytes = new byte[64];
		System.arraycopy(octetKeyPair.getD().decode(), 0, privateKeyBytes, 0, 32);
		System.arraycopy(octetKeyPair.getX().decode(), 0, privateKeyBytes, 32, 32);

		return privateKeyBytes;
	}

	public static byte[] JWK_to_X25519PrivateKeyBytes(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKeyType())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKeyType());

		com.nimbusds.jose.jwk.OctetKeyPair octetKeyPair = (com.nimbusds.jose.jwk.OctetKeyPair) jsonWebKey;
		if (! Curve.X25519.equals(octetKeyPair.getCurve())) throw new IllegalArgumentException("Incorrect curve: " + octetKeyPair.getCurve());

		byte[] privateKeyBytes = new byte[64];
		System.arraycopy(octetKeyPair.getD().decode(), 0, privateKeyBytes, 0, 32);
		System.arraycopy(octetKeyPair.getX().decode(), 0, privateKeyBytes, 32, 32);

		return privateKeyBytes;
	}
}
