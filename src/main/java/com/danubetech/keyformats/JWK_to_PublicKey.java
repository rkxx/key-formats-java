package com.danubetech.keyformats;

import bbs.signatures.KeyPair;
import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyType;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import org.bitcoinj.core.ECKey;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class JWK_to_PublicKey {

	public static Object JWK_to_anyPublicKey(JWK jsonWebKey) {

		KeyTypeName keyType = KeyTypeName_for_JWK.keyTypeName_for_JWK(jsonWebKey);

		if (keyType == KeyTypeName.RSA)
			return JWK_to_RSAPublicKey(jsonWebKey);
		else if (keyType == KeyTypeName.secp256k1)
			return JWK_to_secp256k1PublicKey(jsonWebKey);
		else if (keyType == KeyTypeName.BLS12381_G1)
			return JWK_to_BLS12381_G2PublicKeyBytes(jsonWebKey);
		else if (keyType == KeyTypeName.BLS12381_G2)
			return JWK_to_BLS12381_G2PublicKeyBytes(jsonWebKey);
		else if (keyType == KeyTypeName.Ed25519)
			return JWK_to_Ed25519PublicKeyBytes(jsonWebKey);
		else if (keyType == KeyTypeName.X25519)
			return JWK_to_X25519PublicKeyBytes(jsonWebKey);
		else
			throw new IllegalArgumentException("Unsupported key type: " + keyType);
	}

	public static RSAPublicKey JWK_to_RSAPublicKey(JWK jsonWebKey) {

		if (! KeyType.RSA.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(new BigInteger(jsonWebKey.getNdecoded()), new BigInteger(jsonWebKey.getEdecoded()));
			return (RSAPublicKey) keyFactory.generatePrivate(rsaPublicKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}
	}

	public static byte[] JWK_to_RSAPublicKeyBytes(JWK jsonWebKey) {

		if (! KeyType.RSA.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());

		return JWK_to_RSAPublicKey(jsonWebKey).getEncoded();
	}

	public static ECKey JWK_to_secp256k1PublicKey(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.secp256k1.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return ECKey.fromPublicOnly(jsonWebKey.getXdecoded());
	}

	public static byte[] JWK_to_secp256k1PublicKeyBytes(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.secp256k1.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return jsonWebKey.getXdecoded();
	}

	public static byte[] JWK_to_BLS12381_G1PublicKeyBytes(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.BLS12381_G1.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return jsonWebKey.getXdecoded();
	}

	public static byte[] JWK_to_BLS12381_G2PublicKeyBytes(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.BLS12381_G2.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return jsonWebKey.getXdecoded();
	}

	public static byte[] JWK_to_Ed25519PublicKeyBytes(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.Ed25519.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return jsonWebKey.getXdecoded();
	}

	public static byte[] JWK_to_X25519PublicKeyBytes(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.X25519.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return jsonWebKey.getXdecoded();
	}
}
