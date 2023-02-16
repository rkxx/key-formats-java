package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.Bbs;
import bbs.signatures.KeyPair;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;
import java.util.List;

public class BBSPlus_PublicKeyVerifier extends PublicKeyVerifier<byte[]> {

    public BBSPlus_PublicKeyVerifier(byte[] publicKey) {
        super(publicKey, JWSAlgorithm.BBSPlus);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {
        return verify(List.of(content), signature);
    }

    public boolean verify(List<byte[]> content, byte[] signature) throws GeneralSecurityException {
        try {
            return Bbs.blsVerify(getPublicKey(), signature, content.toArray(new byte[content.size()][]));
        } catch (GeneralSecurityException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }

}
