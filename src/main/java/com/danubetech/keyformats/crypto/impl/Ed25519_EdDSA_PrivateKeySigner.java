package com.danubetech.keyformats.crypto.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.crypto.provider.Ed25519Provider;

import java.security.GeneralSecurityException;

public class Ed25519_EdDSA_PrivateKeySigner extends PrivateKeySigner<byte[]> {

	public Ed25519_EdDSA_PrivateKeySigner(byte[] privateKey) {

		super(privateKey, JWSAlgorithm.EdDSA.getName());
	}

	@Override
	public byte[] sign(byte[] content) throws GeneralSecurityException {

		return Ed25519Provider.get().sign(content, this.getPrivateKey());
	}
}
