package com.danubetech.keyformats.jose;

import com.danubetech.keyformats.PrivateKey_to_JWK;
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JWKTest {

	@Test
	public void testParseJWK() throws Exception {
		BufferedReader reader = new BufferedReader(new InputStreamReader(JWKTest.class.getResourceAsStream("jwks.txt"), StandardCharsets.UTF_8));
		String line;
		while ((line = reader.readLine()) != null) {
			JWK.fromJson(line);
		}
		reader.close();
	}

	@Test
	public void testGetDecodedDandX() throws Exception {
		byte[] publicKey = new byte[32];
		byte[] privateKey = new byte[64];
		TinkEd25519Provider.get().generateEC25519KeyPair(publicKey, privateKey);
		JWK jwkPrivateKey = PrivateKey_to_JWK.Ed25519PrivateKeyBytes_to_JWK(privateKey, "key-1", "sig");
		JWK jwkPublicKey = PrivateKey_to_JWK.Ed25519PrivateKeyBytes_to_JWK(privateKey, "key-1", "sig");
		assertEquals(Hex.encodeHexString(jwkPublicKey.getXdecoded()), Hex.encodeHexString(publicKey));
		assertEquals(Hex.encodeHexString(jwkPublicKey.getDdecoded()) + Hex.encodeHexString(jwkPublicKey.getXdecoded()), Hex.encodeHexString(privateKey));
	}
}
