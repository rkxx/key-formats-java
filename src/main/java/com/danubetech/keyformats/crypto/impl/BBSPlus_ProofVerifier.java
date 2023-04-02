package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.Bbs;
import com.danubetech.keyformats.crypto.ProofVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;
import java.util.List;

public class BBSPlus_ProofVerifier extends ProofVerifier {

    final private byte[] publicKey;
    final private byte[] nonce;

    public BBSPlus_ProofVerifier(byte[] publicKey, byte[] nonce) {
        super( JWSAlgorithm.BBSPlus);
        this.publicKey = publicKey;
        this.nonce = nonce;
    }

    @Override
    protected boolean verify(byte[] proof, List<byte[]> revealedMessages) throws GeneralSecurityException {
        try {
            return Bbs.blsVerifyProof(publicKey, proof, nonce, revealedMessages.toArray(new byte[revealedMessages.size()][]));
        } catch (GeneralSecurityException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }

    public byte[] getPublicKey(){return publicKey;}
    public byte[] getNonce(){return nonce;}

}
