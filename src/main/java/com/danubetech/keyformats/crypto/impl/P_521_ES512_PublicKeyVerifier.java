package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

public class P_521_ES512_PublicKeyVerifier extends PublicKeyVerifier<ECPublicKey> {

    public P_521_ES512_PublicKeyVerifier(ECPublicKey publicKey) {

        super(publicKey, JWSAlgorithm.ES512);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        Signature jcaSignature = Signature.getInstance("SHA512withECDSA");

        jcaSignature.initVerify(this.getPublicKey());
        jcaSignature.update(content);

        return jcaSignature.verify(signature);
    }
}
