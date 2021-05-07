package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.Bbs;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.bitcoinj.core.ECKey;

import java.security.GeneralSecurityException;

public class BLS12381_G2_BBSPlus_PublicKeyVerifier extends PublicKeyVerifier<ECKey> {

    public BLS12381_G2_BBSPlus_PublicKeyVerifier(ECKey publicKey) {

        super(publicKey, JWSAlgorithm.BBSPlus);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        try {

            return Bbs.blsVerify(this.getPublicKey().getPubKey(), signature, new byte[][]{signature});
        } catch (GeneralSecurityException ex) {

            throw ex;
        } catch (Exception ex) {

            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
