/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 *
 * The Universal Permissive License (UPL), Version 1.0
 *
 * Subject to the condition set forth below, permission is hereby granted to any
 * person obtaining a copy of this software, associated documentation and/or data
 * (collectively the "Software"), free of charge and under any and all copyright
 * rights in the Software, and any and all patent rights owned or freely
 * licensable by each licensor hereunder covering either (i) the unmodified
 * Software as contributed to or provided by such licensor, or (ii) the Larger
 * Works (as defined below), to deal in both
 *
 * (a) the Software, and
 *
 * (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
 * one is included with the Software (each a "Larger Work" to which the Software
 * is contributed by such licensors),
 *
 * without restriction, including without limitation the rights to copy, create
 * derivative works of, display, perform, and distribute the Software and make,
 * use, sell, offer for sale, import, export, have made, and have sold the
 * Software and the Larger Work(s), and to sublicense the foregoing rights on
 * either these or other terms.
 *
 * This license is subject to the following condition:
 *
 * The above copyright notice and either this complete permission notice or at
 * a minimum a reference to the UPL must be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.oracle.test.integration.symciph;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.testdata.WrapCipherTestVector;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests for Cipher API calls for key wrap cipher.
 */
public class WrapCipherTest {

    WrapCipherTestVector tv;
    String keyAlg;

    @Before
    public void setUp() throws Exception {
        this.tv = TestData.getFirst(WrapCipherTestVector.class,
                DataMatchers.alg("AESWrapPad"));
        this.keyAlg = "AES";
    }

    Cipher getInitCipher(int mode) throws Exception {
        Cipher c = ProviderUtil.getCipher(tv.getAlg());
        c.init(mode, new SecretKeySpec(tv.getKey(), 0, tv.getKey().length, keyAlg));
        return c;
    }

    @Test
    public void getInstanceAlgPadding() throws Exception {
        Cipher c = ProviderUtil.getCipher(tv.getAlg() + "/ECB/NoPadding");
        c.init(Cipher.WRAP_MODE, new SecretKeySpec(tv.getKey(), 0, tv.getKey().length, keyAlg));
        byte[] wrapped = c.wrap(new SecretKeySpec(tv.getData(), "key"));
        assertArrayEquals(tv.getCiphertext(), wrapped);
    }

    @Test(expected = NoSuchAlgorithmException.class)
    public void getInstanceBadMode() throws Exception {
        Cipher c = ProviderUtil.getCipher(tv.getAlg() + "/CBC/NoPadding");
    }

    @Test(expected = NoSuchPaddingException.class)
    public void getInstanceBadPadding() throws Exception {
        Cipher c = ProviderUtil.getCipher(tv.getAlg() + "/ECB/BadPadding");
    }

    @Test(expected = IllegalStateException.class)
    public void negTestUpdateAADNotSupported() throws Exception {
        Cipher c = getInitCipher(Cipher.WRAP_MODE);
        c.updateAAD(new byte[10]);
    }

    @Test(expected = IllegalStateException.class)
    public void negTestUpdateAADByteBufferNotSupported() throws Exception {
        Cipher c = getInitCipher(Cipher.WRAP_MODE);
        c.updateAAD(ByteBuffer.wrap(new byte[10]));
    }

    @Test(expected = IllegalStateException.class)
    public void negTestUpdate() throws Exception {
        Cipher c = getInitCipher(Cipher.WRAP_MODE);
        c.update(tv.getData(), 0, tv.getData().length, new byte[tv.getData().length + c.getBlockSize()], 0);
    }

    @Test(expected = IllegalStateException.class)
    public void negTestUpdateRet() throws Exception {
        Cipher c = getInitCipher(Cipher.WRAP_MODE);
        c.update(tv.getData(), 0, tv.getData().length);
    }

    @Test(expected = IllegalStateException.class)
    public void negTestDoFinal() throws Exception {
        Cipher c = getInitCipher(Cipher.WRAP_MODE);
        c.doFinal(tv.getData(), 0, tv.getData().length, new byte[tv.getData().length + c.getBlockSize()], 0);
    }

    @Test(expected = IllegalStateException.class)
    public void negTestDoFinalRet() throws Exception {
        Cipher c = getInitCipher(Cipher.WRAP_MODE);
        c.doFinal(tv.getData(), 0, tv.getData().length);
    }

    @Test
    public void wrapSecretKey() throws Exception {
        Cipher c = getInitCipher(Cipher.WRAP_MODE);
        byte[] out = c.wrap(new SecretKeySpec(tv.getData(), ""));
        assertArrayEquals(tv.getCiphertext(), out);
    }

    @Test
    public void unwrapSecretKey() throws Exception {
        Cipher c = getInitCipher(Cipher.UNWRAP_MODE);
        Key key = c.unwrap(tv.getCiphertext(), "BLAH", Cipher.SECRET_KEY);
        assertTrue(key instanceof SecretKey);
        assertEquals("BLAH", key.getAlgorithm());
        assertArrayEquals(tv.getData(), key.getEncoded());
    }

    @Test
    public void wrapUnwrapPublicKey() throws Exception {
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, alg("EC").secParam("secp256r1"));
        Cipher cipher = getInitCipher(Cipher.WRAP_MODE);
        PublicKey key = KeyUtil.loadPublic("EC", kp.getPub());
        byte[] wrapped = cipher.wrap(key);

        cipher = getInitCipher(Cipher.UNWRAP_MODE);
        Key unwrapped = cipher.unwrap(wrapped, "EC", Cipher.PUBLIC_KEY);
        assertEquals(key, unwrapped);

        try {
            cipher.unwrap(wrapped, "EC", Cipher.PRIVATE_KEY);
            fail("Expected unwrap to PRIVATE_KEY to fail");
        } catch (InvalidKeyException e) {
            // Expected.
        }

        try {
            cipher.unwrap(wrapped, "RSA", Cipher.PUBLIC_KEY);
            fail("Expected unwrap to wrong alg type");
        } catch (InvalidKeyException e) {
            // Expected.
        }
    }

    @Test
    public void wrapUnwrapPrivateKey() throws Exception {
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, alg("EC").secParam("secp256r1"));
        Cipher cipher = getInitCipher(Cipher.WRAP_MODE);
        PrivateKey key = KeyUtil.loadPrivate("EC", kp.getPriv());
        byte[] wrapped = cipher.wrap(key);

        cipher = getInitCipher(Cipher.UNWRAP_MODE);
        Key unwrapped = cipher.unwrap(wrapped, "EC", Cipher.PRIVATE_KEY);
        assertEquals(key, unwrapped);

        try {
            cipher.unwrap(wrapped, "EC", Cipher.PUBLIC_KEY);
            fail("Expected unwrap to PUBLIC_KEY to fail");
        } catch (InvalidKeyException e) {
            // Expected.
        }

        try {
            cipher.unwrap(wrapped, "RSA", Cipher.PRIVATE_KEY);
            fail("Expected unwrap to wrong alg type");
        } catch (InvalidKeyException e) {
            // Expected.
        }

        try {
            cipher.unwrap(wrapped, "DSNAY", Cipher.PRIVATE_KEY);
            fail("Expected unwrap to wrong alg type");
        } catch (NoSuchAlgorithmException e) {
            // Expected.
        }
    }

    @Test
    public void decryptDoFinalShortBufferRetry() throws Exception {
        Cipher c = getInitCipher(Cipher.DECRYPT_MODE);

        byte[] input = tv.getCiphertext();
        byte[] expectedOutput = tv.getData();
        byte[] output = new byte[expectedOutput.length - 1];
        Arrays.fill(output, (byte) 0x55);
        byte[] shortBufferOutput = output.clone();

        try {
            c.doFinal(input, 0, input.length, output, 0);
            fail("Failed to throw ShortBufferException");
        } catch (ShortBufferException e) {
            assertArrayEquals(shortBufferOutput, output);
            output = Arrays.copyOf(output, expectedOutput.length);
            int outputLen = c.doFinal(input, 0, input.length, output, 0);
            output = Arrays.copyOf(output, outputLen);
        }
        assertArrayEquals(expectedOutput, output);
    }

    @Test(expected = IllegalBlockSizeException.class)
    public void wrapDataTooShort() throws Exception {
        Cipher cipher = ProviderUtil.getCipher("AESWrap");
        cipher.init(Cipher.WRAP_MODE, new SecretKeySpec(tv.getKey(), 0, tv.getKey().length, keyAlg));
        cipher.wrap(new SecretKeySpec(new byte[15], "Key"));
    }

    @Test(expected = InvalidKeyException.class)
    public void unwrapDataTooShort() throws Exception {
        Cipher cipher = getInitCipher(Cipher.UNWRAP_MODE);
        cipher.unwrap(new byte[15], "AES", Cipher.SECRET_KEY);
    }

    @Test(expected = InvalidKeyException.class)
    public void unwrapDecryptFailure() throws Exception {
        Cipher cipher = getInitCipher(Cipher.UNWRAP_MODE);
        cipher.unwrap(new byte[16], "AES", Cipher.SECRET_KEY);
    }

    @Test
    public void getParameters() throws Exception {
        Cipher c = ProviderUtil.getCipher(tv.getAlg());
        assertNull(c.getParameters());
    }

    @Test
    public void getIV() throws Exception {
        Cipher c = ProviderUtil.getCipher(tv.getAlg());
        assertNull(c.getIV());
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initAlgorithmParametersInvalid() throws Exception {
        Cipher c = ProviderUtil.getCipher(tv.getAlg());
        c.init(Cipher.WRAP_MODE, new SecretKeySpec(tv.getKey(), 0, tv.getKey().length, keyAlg), new IvParameterSpec(new byte[16]));
    }

    @Test
    public void reuseCipher() throws Exception {
        Cipher c = getInitCipher(Cipher.WRAP_MODE);
        byte[] result = c.wrap(new SecretKeySpec(tv.getData(), "Key"));

        byte[] result1 = c.wrap(new SecretKeySpec(new byte[32], "Key1"));

        byte[] result2 = c.wrap(new SecretKeySpec(tv.getData(), "Key2"));
        assertArrayEquals(result, result2);

        c.init(Cipher.UNWRAP_MODE, new SecretKeySpec(tv.getKey(), "AES"));
        Key dec1 = c.unwrap(result1, "AES", Cipher.SECRET_KEY);
        assertArrayEquals(new byte[32], dec1.getEncoded());

        Key dec2 = c.unwrap(result2, "AES", Cipher.SECRET_KEY);
        assertArrayEquals(tv.getData(), dec2.getEncoded());
    }

}
