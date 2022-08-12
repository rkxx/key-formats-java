package com.danubetech.keyformats;

import bbs.signatures.KeyPair;
import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyType;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

public class PublicKey_to_JWK {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static JWK RSAPublicKey_to_JWK(RSAPublicKey publicKey, String kid, String use) {

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.RSA);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setN(Base64.encodeBase64URLSafeString(publicKey.getModulus().toByteArray()));
		jsonWebKey.setE(Base64.encodeBase64URLSafeString(publicKey.getPublicExponent().toByteArray()));

		return jsonWebKey;
	}

	public static JWK RSAPublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		RSAPublicKey publicKey;
		try {
			publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return RSAPublicKey_to_JWK(publicKey, kid, use);
	}

	public static JWK secp256k1PublicKey_to_JWK(ECKey publicKey, String kid, String use) {

		ECPoint publicKeyPoint = publicKey.getPubKeyPoint();

		if (publicKeyPoint.getAffineXCoord().getEncoded().length != 32) throw new IllegalArgumentException("Invalid 'x' value (not 32 bytes): " + Hex.encodeHexString(publicKeyPoint.getAffineXCoord().getEncoded()) + ", length=" + publicKeyPoint.getAffineXCoord().getEncoded().length);
		if (publicKeyPoint.getAffineYCoord().getEncoded().length != 32) throw new IllegalArgumentException("Invalid 'y' value (not 32 bytes): " + Hex.encodeHexString(publicKeyPoint.getAffineYCoord().getEncoded()) + ", length=" + publicKeyPoint.getAffineYCoord().getEncoded().length);

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.secp256k1);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyPoint.getAffineXCoord().getEncoded()));
		jsonWebKey.setY(Base64.encodeBase64URLSafeString(publicKeyPoint.getAffineYCoord().getEncoded()));

		return jsonWebKey;
	}

	public static JWK secp256k1PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		ECKey publicKey = ECKey.fromPublicOnly(publicKeyBytes);

		return secp256k1PublicKey_to_JWK(publicKey, kid, use);
	}

	public static JWK Bls12381G1PublicKey_to_JWK(KeyPair publicKey, String kid, String use) {

		byte[] publicKeyBytes = publicKey.publicKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Bls12381G1);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyBytes));

		return jsonWebKey;
	}

	public static JWK Bls12381G1PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		KeyPair publicKey = new KeyPair(publicKeyBytes, null);

		return Bls12381G1PublicKey_to_JWK(publicKey, kid, use);
	}

	public static JWK Bls12381G2PublicKey_to_JWK(KeyPair publicKey, String kid, String use) {

		byte[] publicKeyBytes = publicKey.publicKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Bls12381G2);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyBytes));

		return jsonWebKey;
	}

	public static JWK Bls12381G2PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		KeyPair publicKey = new KeyPair(publicKeyBytes, null);

		return Bls12381G2PublicKey_to_JWK(publicKey, kid, use);
	}

	public static JWK Ed25519PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Ed25519);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyBytes));

		return jsonWebKey;
	}

	public static JWK X25519PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.X25519);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyBytes));

		return jsonWebKey;
	}

	public static JWK P_256PublicKey_to_JWK(ECKey publicKey, String kid, String use) {

		ECPoint publicKeyPoint = publicKey.getPubKeyPoint();

		if (publicKeyPoint.getAffineXCoord().getEncoded().length != 32) throw new IllegalArgumentException("Invalid 'x' value (not 32 bytes): " + Hex.encodeHexString(publicKeyPoint.getAffineXCoord().getEncoded()) + ", length=" + publicKeyPoint.getAffineXCoord().getEncoded().length);
		if (publicKeyPoint.getAffineYCoord().getEncoded().length != 32) throw new IllegalArgumentException("Invalid 'y' value (not 32 bytes): " + Hex.encodeHexString(publicKeyPoint.getAffineYCoord().getEncoded()) + ", length=" + publicKeyPoint.getAffineYCoord().getEncoded().length);

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.P_256);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyPoint.getAffineXCoord().getEncoded()));
		jsonWebKey.setY(Base64.encodeBase64URLSafeString(publicKeyPoint.getAffineYCoord().getEncoded()));

		return jsonWebKey;
	}

	public static JWK P_256PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		ECKey publicKey = ECKey.fromPublicOnly(publicKeyBytes);

		return P_256PublicKey_to_JWK(publicKey, kid, use);
	}

	public static JWK P_384PublicKey_to_JWK(ECKey publicKey, String kid, String use) {

		ECPoint publicKeyPoint = publicKey.getPubKeyPoint();

		if (publicKeyPoint.getAffineXCoord().getEncoded().length != 48) throw new IllegalArgumentException("Invalid 'x' value (not 48 bytes): " + Hex.encodeHexString(publicKeyPoint.getAffineXCoord().getEncoded()) + ", length=" + publicKeyPoint.getAffineXCoord().getEncoded().length);
		if (publicKeyPoint.getAffineYCoord().getEncoded().length != 48) throw new IllegalArgumentException("Invalid 'y' value (not 48 bytes): " + Hex.encodeHexString(publicKeyPoint.getAffineYCoord().getEncoded()) + ", length=" + publicKeyPoint.getAffineYCoord().getEncoded().length);

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.P_384);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyPoint.getAffineXCoord().getEncoded()));
		jsonWebKey.setY(Base64.encodeBase64URLSafeString(publicKeyPoint.getAffineYCoord().getEncoded()));

		return jsonWebKey;
	}

	public static JWK P_384PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		ECKey publicKey = ECKey.fromPublicOnly(publicKeyBytes);

		return P_384PublicKey_to_JWK(publicKey, kid, use);
	}
}
