package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.Bbs;
import bbs.signatures.ProofMessage;
import com.danubetech.keyformats.crypto.Proofer;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;
import java.util.List;

public class BBSPlus_Proofer extends Proofer {
    final private byte[] publicKey;
    final private byte[] nonce;
    public BBSPlus_Proofer(byte[] publicKey, byte[] nonce) {
        super( JWSAlgorithm.BBSPlus);
        this.publicKey = publicKey;
        this.nonce = nonce;
    }

    @Override
    protected byte[] deriveProof(byte[] signature, List<ProofMessage> messages) throws GeneralSecurityException {
        try {
            return Bbs.blsCreateProof(publicKey, nonce, signature, messages.toArray(new ProofMessage[messages.size()]));
        } catch (GeneralSecurityException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }

    public byte[] getPublicKey(){return publicKey;}
    public byte[] getNonce(){return nonce;}

}
