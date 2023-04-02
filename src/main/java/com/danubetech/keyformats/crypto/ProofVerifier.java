package com.danubetech.keyformats.crypto;

import java.security.GeneralSecurityException;
import java.util.List;

public abstract class ProofVerifier {

	private final String algorithm;

	protected ProofVerifier(String algorithm) {

		this.algorithm = algorithm;
	}

	public final boolean verify(byte[] proof, List<byte[]> revealedMessages, String algorithm) throws GeneralSecurityException {

		if (! algorithm.equals(this.algorithm)) throw new GeneralSecurityException("Unexpected algorithm " + algorithm + " is different from " + this.algorithm);

		return this.verify(proof, revealedMessages);
	}

	protected abstract boolean verify(byte[] proof, List<byte[]> revealedMessages) throws GeneralSecurityException;

	public String getAlgorithm() {

		return this.algorithm;
	}
}
