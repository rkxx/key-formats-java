package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.Bbs;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;

public class Bls12381G2_BBSPlus_PublicKeyVerifier extends PublicKeyVerifier<ECPublicKey> {

    public Bls12381G2_BBSPlus_PublicKeyVerifier(ECPublicKey publicKey) {

        super(publicKey, JWSAlgorithm.BBSPlus);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        try {

            return Bbs.blsVerify(this.getPublicKey().getEncoded(), signature, new byte[][]{signature});
        } catch (GeneralSecurityException ex) {

            throw ex;
        } catch (Exception ex) {

            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
