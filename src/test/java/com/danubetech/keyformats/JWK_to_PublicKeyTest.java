package com.danubetech.keyformats;
import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.danubetech.keyformats.crypto.provider.impl.NaClSodiumEd25519Provider;
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider;
import com.danubetech.keyformats.jose.JWK;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class JWK_to_PublicKeyTest {

	static final JWK rsaJwk;
	static final JWK secp256k1Jwk;
	static final JWK ed25519Jwk;
	static final JWK x25519Jwk;
	static final JWK p_256Jwk;
	static final JWK p_384Jwk;

	static {
		try {
			rsaJwk = JWK.fromJson("{\n" +
					"        \"kty\": \"RSA\",\n" +
					"        \"n\": \"yeNlzlub94YgerT030codqEztjfU_S6X4DbDA_iVKkjAWtYfPHDzz_sPCT1Axz6isZdf3lHpq_gYX4Sz-cbe4rjmigxUxr-FgKHQy3HeCdK6hNq9ASQvMK9LBOpXDNn7mei6RZWom4wo3CMvvsY1w8tjtfLb-yQwJPltHxShZq5-ihC9irpLI9xEBTgG12q5lGIFPhTl_7inA1PFK97LuSLnTJzW0bj096v_TMDg7pOWm_zHtF53qbVsI0e3v5nmdKXdFf9BjIARRfVrbxVxiZHjU6zL6jY5QJdh1QCmENoejj_ytspMmGW7yMRxzUqgxcAqOBpVm0b-_mW3HoBdjQ\",\n" +
					"        \"e\": \"AQAB\"\n" +
					"      }");
			secp256k1Jwk = JWK.fromJson("{\n" +
					"        \"kty\": \"EC\",\n" +
					"        \"crv\": \"secp256k1\",\n" +
					"        \"x\": \"WfY7Px6AgH6x-_dgAoRbg8weYRJA36ON-gQiFnETrqw\",\n" +
					"        \"y\": \"IzFx3BUGztK0cyDStiunXbrZYYTtKbOUzx16SUK0sAY\"\n" +
					"      }");
			ed25519Jwk = JWK.fromJson("{\n" +
					"          \"kty\": \"OKP\",\n" +
					"          \"crv\": \"Ed25519\",\n" +
					"          \"x\": \"7kqc5NnojHJHZ11Ec5cGCLMIKgJVDBKhrAbu9YrfVFg\"\n" +
					"        }");
			x25519Jwk = JWK.fromJson("{\n" +
					"          \"kty\": \"OKP\",\n" +
					"          \"crv\": \"X25519\",\n" +
					"          \"x\": \"1KHivX4x0Pf8Odhs_vCAptOCWXzeo9fIFKfhIwdKhCc\"\n" +
					"        }");
			p_256Jwk = JWK.fromJson("{\n" +
					"          \"kty\":\"EC\",\n" +
					"          \"crv\":\"P-256\",\n" +
					"          \"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\n" +
					"          \"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"\n" +
					"}");
			p_384Jwk = JWK.fromJson("{\n" +
					"          \"kty\": \"EC\",\n" +
					"          \"crv\": \"P-384\",\n" +
					"          \"x\": \"Yu5u-jiP9VnSW2-Y7GaoBodTtYpfm8jdyeGQ6_dlm-iSpeNEElTngR8Z_vIc61MI\",\n" +
					"          \"y\": \"wkU01ZZze9IlPYSYcQ1OU1KIZaAdO_xxwk_zwk35TO19FrnRXEomGKYZ2UZpuNrs\"\n" +
					"        }");
		} catch (IOException ex) {
			throw new ExceptionInInitializerError(ex);
		}
	}

	@Test
	public void testJWK_to_PublicKey() throws Exception {
		byte[] rsaBytes = JWK_to_PublicKey.JWK_to_RSAPublicKeyBytes(rsaJwk);
		byte[] sep256k1Bytes = JWK_to_PublicKey.JWK_to_secp256k1PublicKeyBytes(secp256k1Jwk);
		byte[] ed25519Bytes = JWK_to_PublicKey.JWK_to_Ed25519PublicKeyBytes(ed25519Jwk);
		byte[] x25519Bytes = JWK_to_PublicKey.JWK_to_X25519PublicKeyBytes(x25519Jwk);
		byte[] p_256Bytes = JWK_to_PublicKey.JWK_to_P_256PublicKeyBytes(p_256Jwk);
		byte[] p_384Bytes = JWK_to_PublicKey.JWK_to_P_384PublicKeyBytes(p_384Jwk);
		JWK rsaJwk2 = PublicKey_to_JWK.RSAPublicKeyBytes_to_JWK(rsaBytes, null, null);
		JWK secp256k1Jwk2 = PublicKey_to_JWK.RSAPublicKeyBytes_to_JWK(sep256k1Bytes, null, null);
		JWK ed25519Jwk2 = PublicKey_to_JWK.Ed25519PublicKeyBytes_to_JWK(ed25519Bytes, null, null);
		JWK x25519Jwk2 = PublicKey_to_JWK.X25519PublicKeyBytes_to_JWK(x25519Bytes, null, null);
		JWK p_256Jwk2 = PublicKey_to_JWK.P_256PublicKeyBytes_to_JWK(p_256Bytes, null, null);
		JWK p_384Jwk2 = PublicKey_to_JWK.P_384PublicKeyBytes_to_JWK(p_384Bytes, null, null);
		assertEquals(rsaJwk, rsaJwk2);
		assertEquals(secp256k1Jwk, secp256k1Jwk2);
		assertEquals(ed25519Jwk, ed25519Jwk2);
		assertEquals(x25519Jwk, x25519Jwk2);
		assertEquals(p_256Jwk, p_256Jwk2);
		assertEquals(p_384Jwk, p_384Jwk2);
	}
}
