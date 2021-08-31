package com.danubetech.keyformats;

import bbs.signatures.KeyPair;
import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyType;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Point;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
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
		} catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
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

		return ECKey.fromPublicOnly(JWK_to_secp256k1PublicKeyBytes(jsonWebKey));
	}

	public static byte[] JWK_to_secp256k1PublicKeyBytes(JWK jsonWebKey) {

		if (! KeyType.EC.equals(jsonWebKey.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jsonWebKey.getKty());
		if (! Curve.secp256k1.equals(jsonWebKey.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jsonWebKey.getCrv());

		byte[] xDecoded = jsonWebKey.getXdecoded();
		if (xDecoded.length != 32) throw new IllegalArgumentException("Invalid 'x' value (not 32 bytes): " + jsonWebKey.getX() + ", length=" + jsonWebKey.getXdecoded().length);
		byte[] yDecoded = jsonWebKey.getYdecoded();
		if (yDecoded.length != 32) throw new IllegalArgumentException("Invalid 'y' value (not 32 bytes): " + jsonWebKey.getY() + ", length=" + jsonWebKey.getYdecoded().length);

		byte[] publicKeyBytes = new byte[65];
		publicKeyBytes[0] = 4;
		System.arraycopy(xDecoded, 0, publicKeyBytes, 1, 32);
		System.arraycopy(yDecoded, 0, publicKeyBytes, 33, 32);

		return publicKeyBytes;
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
