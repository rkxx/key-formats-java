package com.danubetech.keyformats.crypto.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.danubetech.keyformats.crypto.PrivateKeySigner;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;

public class RSA_RS256_PrivateKeySigner extends PrivateKeySigner<RSAPrivateKey> {

	public RSA_RS256_PrivateKeySigner(RSAPrivateKey privateKey) {

		super(privateKey, JWSAlgorithm.RS256.getName());
	}

	@Override
	public byte[] sign(byte[] content) throws GeneralSecurityException {

		Signature jcaSignature = Signature.getInstance("SHA256withRSA");

		jcaSignature.initSign(this.getPrivateKey());
		jcaSignature.update(content);

		return jcaSignature.sign();
	}
}
