package com.danubetech.keyformats;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bitcoinj.core.ECKey;
import org.bouncycastle.math.ec.ECPoint;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64URL;

public class PrivateKeyToJWK {

	public static JWK RSAPrivateKeyToJWK(RSAPrivateKey privateKey, RSAPublicKey publicKey, String kid, String use) {

		JWK jsonWebKey = new com.nimbusds.jose.jwk.RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(kid)
				.keyUse(use == null ? null : new KeyUse(use))
				.build();

		return jsonWebKey;
	}

	public static JWK P_256KPrivateKeyToJWK(ECKey privateKey, String kid, String use) {

		ECPoint publicKeyPoint = privateKey.getPubKeyPoint();
		byte[] privateKeyBytes = privateKey.getPrivKeyBytes();
		Base64URL xParameter = Base64URL.encode(publicKeyPoint.getAffineXCoord().getEncoded());
		Base64URL yParameter = Base64URL.encode(publicKeyPoint.getAffineYCoord().getEncoded());
		Base64URL dParameter = Base64URL.encode(privateKeyBytes);

		JWK jsonWebKey = new com.nimbusds.jose.jwk.ECKey.Builder(Curve.P_256K, xParameter, yParameter)
				.d(dParameter)
				.keyID(kid)
				.keyUse(use == null ? null : new KeyUse(use))
				.build();

		return jsonWebKey;
	}

	public static JWK P_256KPrivateKeyBytesToJWK(byte[] privateKeyBytes, String kid, String use) {

		ECKey privateKey = ECKey.fromPrivate(privateKeyBytes);

		return P_256KPrivateKeyToJWK(privateKey, kid, use);
	}

	public static JWK Ed25519PrivateKeyBytesToJWK(byte[] privateKeyBytes, byte[] publicKeyBytes, String kid, String use) {

		Base64URL xParameter = Base64URL.encode(publicKeyBytes);
		Base64URL dParameter = Base64URL.encode(privateKeyBytes);

		JWK jsonWebKey = new com.nimbusds.jose.jwk.OctetKeyPair.Builder(Curve.Ed25519, xParameter)
				.d(dParameter)
				.keyID(kid)
				.keyUse(use == null ? null : new KeyUse(use))
				.build();

		return jsonWebKey;
	}

	public static JWK X25519PrivateKeyBytesToJWK(byte[] privateKeyBytes, byte[] publicKeyBytes, String kid, String use) {

		Base64URL xParameter = Base64URL.encode(publicKeyBytes);
		Base64URL dParameter = Base64URL.encode(privateKeyBytes);

		JWK jsonWebKey = new com.nimbusds.jose.jwk.OctetKeyPair.Builder(Curve.X25519, xParameter)
				.d(dParameter)
				.keyID(kid)
				.keyUse(use == null ? null : new KeyUse(use))
				.build();

		return jsonWebKey;
	}
}
