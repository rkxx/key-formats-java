package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.Bbs;
import com.danubetech.keyformats.jose.JWSAlgorithms;
import com.danubetech.keyformats.crypto.PrivateKeySigner;
import org.bitcoinj.core.ECKey;

import java.security.GeneralSecurityException;

public class BLS12381_G1_BBSPlus_PrivateKeySigner extends PrivateKeySigner<ECKey> {

    public BLS12381_G1_BBSPlus_PrivateKeySigner(ECKey privateKey) {

        super(privateKey, JWSAlgorithms.BBSPlus.getName());
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        try {

            return Bbs.sign(this.getPrivateKey().getPrivKeyBytes(), this.getPrivateKey().getPubKey(), new byte[][]{content});
        } catch (GeneralSecurityException ex) {

            throw ex;
        } catch (Exception ex) {

            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
