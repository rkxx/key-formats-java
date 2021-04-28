package com.danubetech.keyformats;

import java.security.interfaces.RSAPrivateKey;

import bbs.signatures.KeyPair;
import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyType;
import com.danubetech.keyformats.jose.KeyTypeName;
import org.bitcoinj.core.ECKey;

import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;

public class JWK_to_PrivateKey {

	public static Object JWK_to_anyPrivateKey(JWK jsonWebKey) {

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

	public static RSAPrivateKey JWK_to_RSAPrivateKey(JWK jsonWebKey) {

		if (! KeyType.RSA.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());

		throw new RuntimeException("Not supported");
//		return ((RSAKey) jsonWebKey).toRSAPrivateKey();
	}

	public static ECKey JWK_to_secp256k1PrivateKey(JWK jsonWebKey) {

		byte[] privateKeyBytes = JWK_to_secp256k1PrivateKeyBytes(jsonWebKey);

		return ECKey.fromPrivate(privateKeyBytes);
	}

	public static byte[] JWK_to_secp256k1PrivateKeyBytes(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.secp256k1.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return jsonWebKey.getDdecoded();
	}

	public static KeyPair JWK_to_BLS12381_G1PrivateKey(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.BLS12381_G1.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return new KeyPair(jsonWebKey.getXdecoded(), jsonWebKey.getDdecoded());
	}

	public static byte[] JWK_to_BLS12381_G1PrivateKeyBytes(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.BLS12381_G1.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return jsonWebKey.getDdecoded();
	}

	public static KeyPair JWK_to_BLS12381_G2PrivateKey(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.BLS12381_G2.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return new KeyPair(jsonWebKey.getXdecoded(), jsonWebKey.getDdecoded());
	}

	public static byte[] JWK_to_BLS12381_G2PrivateKeyBytes(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.BLS12381_G2.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		return jsonWebKey.getDdecoded();
	}

	public static byte[] JWK_to_Ed25519PrivateKeyBytes(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.Ed25519.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		byte[] privateKeyBytes = new byte[64];
		System.arraycopy(jsonWebKey.getDdecoded(), 0, privateKeyBytes, 0, 32);
		System.arraycopy(jsonWebKey.getXdecoded(), 0, privateKeyBytes, 32, 32);

		return privateKeyBytes;
	}

	public static byte[] JWK_to_X25519PrivateKeyBytes(JWK jsonWebKey) {

		if (! KeyType.OKP.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.X25519.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		byte[] privateKeyBytes = new byte[64];
		System.arraycopy(jsonWebKey.getDdecoded(), 0, privateKeyBytes, 0, 32);
		System.arraycopy(jsonWebKey.getXdecoded(), 0, privateKeyBytes, 32, 32);

		return privateKeyBytes;
	}
}
