package com.danubetech.keyformats;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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

		throw new RuntimeException("Not supported");

/*		com.nimbusds.jose.jwk.RSAKey jsonWebKey = new com.nimbusds.jose.jwk.RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(kid)
				.keyUse(use == null ? null : new KeyUse(use))
				.build();

		return jsonWebKey;*/
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

	public static JWK BLS12381_G1PrivateKey_to_JWK(KeyPair privateKey, String kid, String use) {

		byte[] publicKeyBytes = privateKey.publicKey;
		byte[] privateKeyBytes = privateKey.secretKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.BLS12381_G1);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyBytes));
		jsonWebKey.setD(Base64.encodeBase64URLSafeString(privateKeyBytes));

		return jsonWebKey;
	}

	public static JWK BLS12381_G1PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, byte[] publicKeyBytes, String kid, String use) {

		KeyPair privateKey = new KeyPair(publicKeyBytes, privateKeyBytes);

		return BLS12381_G1PrivateKey_to_JWK(privateKey, kid, use);
	}

	public static JWK BLS12381_G2PrivateKey_to_JWK(KeyPair privateKey, String kid, String use) {

		byte[] publicKeyBytes = privateKey.publicKey;
		byte[] privateKeyBytes = privateKey.secretKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.BLS12381_G2);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyBytes));
		jsonWebKey.setD(Base64.encodeBase64URLSafeString(privateKeyBytes));

		return jsonWebKey;
	}

	public static JWK BLS12381_G2PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, byte[] publicKeyBytes, String kid, String use) {

		KeyPair privateKey = new KeyPair(publicKeyBytes, privateKeyBytes);

		return BLS12381_G2PrivateKey_to_JWK(privateKey, kid, use);
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
