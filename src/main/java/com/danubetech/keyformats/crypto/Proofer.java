package com.danubetech.keyformats.crypto;

import bbs.signatures.ProofMessage;

import java.security.GeneralSecurityException;
import java.util.List;

public abstract class Proofer {

	private final String algorithm;

	protected Proofer(String algorithm) {

		this.algorithm = algorithm;
	}

	public final byte[] deriveProof(byte[] signature, List<ProofMessage> messages, String algorithm) throws GeneralSecurityException {

		if (! algorithm.equals(this.algorithm)) throw new GeneralSecurityException("Unexpected algorithm " + algorithm + " is different from " + this.algorithm);

		return this.deriveProof(signature, messages);
	}

	protected abstract byte[] deriveProof(byte[] signature, List<ProofMessage> messages) throws GeneralSecurityException;

	public String getAlgorithm() {

		return this.algorithm;
	}
}
