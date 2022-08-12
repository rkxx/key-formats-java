package com.danubetech.keyformats;
import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.danubetech.keyformats.crypto.provider.RandomProvider;
import com.danubetech.keyformats.crypto.provider.impl.JavaRandomProvider;
import com.danubetech.keyformats.crypto.provider.impl.NaClSodiumEd25519Provider;
import com.danubetech.keyformats.crypto.provider.impl.NaClSodiumRandomProvider;
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class RandomProviderTest {

	@Test
	public void testNaClSodiumRandomProvider() throws Exception {
		this.internalTest(new NaClSodiumRandomProvider());
	}

	@Test
	public void testJavaRandomProvider() throws Exception {
		this.internalTest(new JavaRandomProvider());
	}

	private void internalTest(RandomProvider randomProvider) throws Exception {
		byte[] zeros = new byte[1024];
		Arrays.fill(zeros, (byte) 0);
		byte[] random1 = randomProvider.randomBytes(1024);
		byte[] random2 = randomProvider.randomBytes(1024);
		assertEquals(random1.length, 1024);
		assertEquals(random2.length, 1024);
		assertFalse(Arrays.equals(random1, random2));
		assertFalse(Arrays.equals(random1, zeros));
		assertFalse(Arrays.equals(random2, zeros));
	}
}
