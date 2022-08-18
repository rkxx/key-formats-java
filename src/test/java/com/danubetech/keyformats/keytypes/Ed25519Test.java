package com.danubetech.keyformats.keytypes;

import com.danubetech.keyformats.*;
import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class Ed25519Test extends AbstractTest {

	static final JWK jwkPublic;
	static final JWK jwkPrivate;

	static {
		try {
			jwkPublic = JWK.fromJson("{\n" +
					"  \"kty\": \"OKP\",\n" +
					"  \"crv\": \"Ed25519\",\n" +
					"  \"x\": \"HBzNvsEpO1VBjGlroD8FO6-nsAjp9hRjxP73vH8CQMw\"\n" +
					"}");
			jwkPrivate = JWK.fromJson("{\n" +
					"  \"kty\": \"OKP\",\n" +
					"  \"crv\": \"Ed25519\",\n" +
					"  \"x\": \"HBzNvsEpO1VBjGlroD8FO6-nsAjp9hRjxP73vH8CQMw\",\n" +
					"  \"d\": \"IP3EFeVIO54b2EyfJ7Urws3qV4rbaShE_Bybbeuac8g\"\n" +
					"}");
		} catch (IOException ex) {
			throw new ExceptionInInitializerError(ex);
		}
	}

	@Override
	KeyTypeName getKeyTypeName() {
		return KeyTypeName.Ed25519;
	}

	@Override
	List<String> getAlgorithms() {
		return Collections.singletonList(JWSAlgorithm.EdDSA);
	}

	@Override
	Object getPrivateKey() {
		return JWK_to_PrivateKey.JWK_to_Ed25519PrivateKey(jwkPrivate);
	}

	@Override
	Object getPublicKey() {
		return JWK_to_PublicKey.JWK_to_Ed25519PublicKey(jwkPublic);
	}

	@Test
	public void testPublicKey() throws Exception {
		byte[] publicKey = JWK_to_PublicKey.JWK_to_Ed25519PublicKey(jwkPublic);
		byte[] publicKeyBytes = PublicKeyBytes.Ed25519PublicKey_to_bytes(publicKey);
		assertEquals(publicKeyBytes.length, 32);

		byte[] publicKey2 = PublicKeyBytes.bytes_to_Ed25519PublicKey(publicKeyBytes);
		assertArrayEquals(publicKey, publicKey2);
		JWK jwk2 = PublicKey_to_JWK.Ed25519PublicKey_to_JWK(publicKey2, null, null);
		assertEquals(jwkPublic, jwk2);
	}

	@Test
	public void testPrivateKey() throws Exception {
		byte[] privateKey = JWK_to_PrivateKey.JWK_to_Ed25519PrivateKey(jwkPrivate);
		byte[] privateKeyBytes = PrivateKeyBytes.Ed25519PrivateKey_to_bytes(privateKey);
		assertEquals(privateKeyBytes.length, 64);

		byte[] privateKey2 = PrivateKeyBytes.bytes_to_Ed25519PrivateKey(privateKeyBytes);
		assertArrayEquals(privateKey, privateKey2);
		JWK jwk2 = PrivateKey_to_JWK.Ed25519PrivateKey_to_JWK(privateKey2, null, null);
		assertEquals(jwkPrivate, jwk2);
	}
}
