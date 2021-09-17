package com.danubetech.keyformats;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import bbs.signatures.KeyPair;
import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyType;
import org.apache.commons.codec.binary.Base64;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.math.ec.ECPoint;

public class PrivateKey_to_JWK {

	public static JWK RSAPrivateKey_to_JWK(RSAPrivateKey privateKey, RSAPublicKey publicKey, String kid, String use) {

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.RSA);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setN(Base64.encodeBase64URLSafeString(privateKey.getModulus().toByteArray()));
		jsonWebKey.setD(Base64.encodeBase64URLSafeString(privateKey.getPrivateExponent().toByteArray()));
		jsonWebKey.setE(Base64.encodeBase64URLSafeString(publicKey.getPublicExponent().toByteArray()));

		return jsonWebKey;
	}

	public static JWK RSAPrivateKeyBytes_to_JWK(byte[] privateKeyBytes, byte[] publicKeyBytes, String kid, String use) {

		RSAPrivateKey privateKey;
		RSAPublicKey publicKey;
		try {
			privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
			publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return RSAPrivateKey_to_JWK(privateKey, publicKey, kid, use);
	}

	public static JWK secp256k1PrivateKey_to_JWK(ECKey privateKey, String kid, String use) {

		ECPoint publicKeyPoint = privateKey.getPubKeyPoint();
		byte[] privateKeyBytes = privateKey.getPrivKeyBytes();

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.secp256k1);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyPoint.getAffineXCoord().getEncoded()));
		jsonWebKey.setY(Base64.encodeBase64URLSafeString(publicKeyPoint.getAffineYCoord().getEncoded()));
		jsonWebKey.setD(Base64.encodeBase64URLSafeString(privateKeyBytes));

		return jsonWebKey;
	}

	public static JWK secp256k1PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {

		ECKey privateKey = ECKey.fromPrivate(privateKeyBytes);

		return secp256k1PrivateKey_to_JWK(privateKey, kid, use);
	}

	public static JWK Bls12381G1PrivateKey_to_JWK(KeyPair privateKey, String kid, String use) {

		byte[] publicKeyBytes = privateKey.publicKey;
		byte[] privateKeyBytes = privateKey.secretKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Bls12381G1);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyBytes));
		jsonWebKey.setD(Base64.encodeBase64URLSafeString(privateKeyBytes));

		return jsonWebKey;
	}

	public static JWK Bls12381G1PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, byte[] publicKeyBytes, String kid, String use) {

		KeyPair privateKey = new KeyPair(publicKeyBytes, privateKeyBytes);

		return Bls12381G1PrivateKey_to_JWK(privateKey, kid, use);
	}

	public static JWK Bls12381G2PrivateKey_to_JWK(KeyPair privateKey, String kid, String use) {

		byte[] publicKeyBytes = privateKey.publicKey;
		byte[] privateKeyBytes = privateKey.secretKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Bls12381G2);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyBytes));
		jsonWebKey.setD(Base64.encodeBase64URLSafeString(privateKeyBytes));

		return jsonWebKey;
	}

	public static JWK Bls12381G2PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, byte[] publicKeyBytes, String kid, String use) {

		KeyPair privateKey = new KeyPair(publicKeyBytes, privateKeyBytes);

		return Bls12381G2PrivateKey_to_JWK(privateKey, kid, use);
	}

	public static JWK Ed25519PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, byte[] publicKeyBytes, String kid, String use) {

		byte[] onlyPrivateKeyBytes = Arrays.copyOf(privateKeyBytes, 32);

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Ed25519);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyBytes));
		jsonWebKey.setD(Base64.encodeBase64URLSafeString(onlyPrivateKeyBytes));

		return jsonWebKey;
	}

	public static JWK X25519PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, byte[] publicKeyBytes, String kid, String use) {

		byte[] onlyPrivateKeyBytes = Arrays.copyOf(privateKeyBytes, 32);

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.X25519);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyBytes));
		jsonWebKey.setD(Base64.encodeBase64URLSafeString(onlyPrivateKeyBytes));

		return jsonWebKey;
	}
}
