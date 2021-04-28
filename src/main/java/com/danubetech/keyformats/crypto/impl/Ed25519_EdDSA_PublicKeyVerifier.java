package com.danubetech.keyformats.crypto.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.crypto.provider.Ed25519Provider;

import java.security.GeneralSecurityException;

public class Ed25519_EdDSA_PublicKeyVerifier extends PublicKeyVerifier<byte[]> {

    public Ed25519_EdDSA_PublicKeyVerifier(byte[] publicKey) {

        super(publicKey, JWSAlgorithm.EdDSA.getName());
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        return Ed25519Provider.get().verify(content, signature, this.getPublicKey());
    }
}
