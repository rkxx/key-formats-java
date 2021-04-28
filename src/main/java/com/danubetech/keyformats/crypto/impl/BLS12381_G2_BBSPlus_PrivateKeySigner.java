package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.Bbs;
import bbs.signatures.KeyPair;
import com.danubetech.keyformats.jose.JWSAlgorithms;
import com.danubetech.keyformats.crypto.PrivateKeySigner;
import org.bitcoinj.core.ECKey;

import java.security.GeneralSecurityException;

public class BLS12381_G2_BBSPlus_PrivateKeySigner extends PrivateKeySigner<KeyPair> {

    public BLS12381_G2_BBSPlus_PrivateKeySigner(KeyPair privateKey) {

        super(privateKey, JWSAlgorithms.BBSPlus.getName());
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        try {

            return Bbs.sign(this.getPrivateKey().secretKey, this.getPrivateKey().publicKey, new byte[][]{content});
        } catch (GeneralSecurityException ex) {

            throw ex;
        } catch (Exception ex) {

            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
