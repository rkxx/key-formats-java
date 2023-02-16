package com.danubetech.keyformats.crypto

import bbs.signatures.Bbs
import com.danubetech.keyformats.crypto.impl.Bls12381G2_BBSPlus_PrivateKeySigner
import com.danubetech.keyformats.crypto.impl.Bls12381G2_BBSPlus_PublicKeyVerifier
import org.junit.jupiter.api.Test
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Bls12381G2_BBSPlusTest {
    @Test
    fun signAndVerifySingleMessage() {
        val content = Random.nextBytes(32)
        val keyPair = Bbs.generateBls12381G2Key(Random.nextBytes(32))
        val signature = Bls12381G2_BBSPlus_PrivateKeySigner(keyPair).run {
            sign(content)
        }
        assertEquals(signature.size, 112)
        val verifyResult = Bls12381G2_BBSPlus_PublicKeyVerifier(keyPair.publicKey).run {
            verify(content, signature)
        }
        assertTrue(verifyResult)
    }

    @Test
    fun signAndVerifyListOfMessages() {
        val content = listOf(Random.nextBytes(32), Random.nextBytes(32), Random.nextBytes(32))
        val keyPair = Bbs.generateBls12381G2Key(Random.nextBytes(32))
        val signature = Bls12381G2_BBSPlus_PrivateKeySigner(keyPair).run {
            sign(content)
        }
        assertEquals(signature.size, 112)
        val verifyResult = Bls12381G2_BBSPlus_PublicKeyVerifier(keyPair.publicKey).run {
            verify(content, signature)
        }
        assertTrue(verifyResult)
    }

}