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

package com.oracle.jipher.internal.spi;

import java.lang.ref.Cleaner;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import com.oracle.jipher.internal.common.Util;
import com.oracle.jipher.internal.openssl.OpenSslException;

import static com.oracle.jipher.internal.common.Util.clearArray;
import static com.oracle.jipher.internal.spi.CipherMode.KW;
import static com.oracle.jipher.internal.spi.CipherMode.KWP;

/**
 * Abstract base class for AES key wrap and wrap-with-padding ciphers.
 * <p>
 * The implementation extends {@link SymmCipher} and handles the buffering of
 * input data, cleanup of sensitive buffers via {@link Cleaner}, and enforces the
 * constraints of the underlying OpenSSL key-wrap algorithms (KW and KWP).
 */
public abstract class WrapCipher extends SymmCipher {

    /**
     * Cleaner instance - used to wipe sensitive byte buffers when the cipher is garbage-collected
     */
    private static final Cleaner CLEANER_INSTANCE = Cleaner.create();

    private static final int UNIT_BYTES = 8;

    /** State record holding the input buffer that will be cleared on cleanup.
     * @param inputBuffer The input buffer to be cleared on cleanup.
     */
    record State(ByteBuffer inputBuffer) implements Runnable {
        @Override
        public void run() {
            clearArray(this.inputBuffer.array());
        }
    }

    private State state;
    private Cleaner.Cleanable cleanable;

    /**
     * Constructs a new {@code WrapCipher} for the given algorithm and mode.
     *
     * @param alg  the {@link CipherAlg} describing the underlying cipher
     * @param mode the {@link CipherMode} - either {@link CipherMode#KW} or
     *             {@link CipherMode#KWP}
     */
    WrapCipher(CipherAlg alg, CipherMode mode) {
        super(alg);
        this.mode = mode;
        this.padding = CipherPadding.NOPADDING;
    }

    void appendToInputBuf(byte[] input, int inOffset, int inLen) {
        if (this.state == null) {
            this.state = new State(ByteBuffer.allocate(inLen));
            if (this.encrypt) {
                // Ensure that the contents of the ByteBuffer are cleared when this WrapCipher is GCed.
                this.cleanable = CLEANER_INSTANCE.register(this, this.state);
            }
        } else if (inLen > this.state.inputBuffer.remaining()) {
            int requiredSize;
            try {
                requiredSize = Math.addExact(this.state.inputBuffer.position(), inLen);
            } catch (ArithmeticException e) {
                throw new ProviderException("JipherJCE provider only supports KeyWrap input data of up to " + Integer.MAX_VALUE + " bytes");
            }
            int newSize = Math.max(this.state.inputBuffer.capacity() < Integer.MAX_VALUE / 2 ?
                    this.state.inputBuffer.capacity() * 2 : 0, requiredSize);
            ByteBuffer oldInputBuffer = this.state.inputBuffer;
            Cleaner.Cleanable oldCleanable = this.cleanable;
            this.state = new State(ByteBuffer.allocate(newSize));
            if (this.encrypt) {
                // Ensure that the contents of the new ByteBuffer instance are cleared when this WrapCipher is GCed.
                this.cleanable = CLEANER_INSTANCE.register(this, this.state);
            }
            oldInputBuffer.flip();
            this.state.inputBuffer.put(oldInputBuffer);

            // Clear the contents of the old ByteBuffer.
            if (oldCleanable != null) {
                oldCleanable.clean();
            }
        }
        this.state.inputBuffer.put(input, inOffset, inLen);
    }

    @Override
    protected void engineSetMode(String s) throws NoSuchAlgorithmException {
        if (!s.equalsIgnoreCase("ECB")) {
            throw new NoSuchAlgorithmException(s + " cannot be used");
        }
    }

    @Override
    protected void engineSetPadding(String s) throws NoSuchPaddingException {
        if (!s.equalsIgnoreCase("NoPadding")) {
            throw new NoSuchPaddingException(s + " cannot be used");
        }
    }

    @Override
    protected void engineInit(int cipherMode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (algorithmParameters != null) {
            throw new InvalidAlgorithmParameterException("Parameters not expected for key wrap cipher");
        }
        super.engineInit(cipherMode, key, (AlgorithmParameters) null, secureRandom);
    }

    @Override
    protected int engineUpdate(byte[] input, int inOffset, int inLen, byte[] out, int outOffset) {
        checkIfInitialized();
        this.updateCalled = true;
        if (inLen > 0) {
            appendToInputBuf(input, inOffset, inLen);
        }
        return 0;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inOffset, int inLen) {
        checkIfInitialized();
        this.updateCalled = true;
        if (inLen > 0) {
            appendToInputBuf(input, inOffset, inLen);
        }
        return new byte[0];
    }

    @Override
    protected int engineDoFinal(byte[] input, int inOffset, int inLen, byte[] out, int outOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkIfInitialized();

        // Check the size of the output buffer before committing to calling cleanup().
        // For decryption in KWP mode the number of output bytes can vary so compare the
        // size of the output buffer against the minimum possible output.
        int outputSize = engineGetOutputSize(inLen);
        int minOutputSize = !this.encrypt && this.mode == KWP && outputSize >= UNIT_BYTES ?
                outputSize - UNIT_BYTES : outputSize;
        if (minOutputSize > out.length - outOffset) {
            throw new ShortBufferException("Not enough space in output array");
        }

        byte[] outputBounceBuffer = null;
        boolean doCleanup = true;
        try {
            int position = this.state != null ? this.state.inputBuffer.position() : 0;

            // For encryption in KW mode, check that the total input is a multiple of UNIT_BYTES.
            // For decryption, check that the total input is both a multiple of UNIT_BYTES and is
            // at least two units in size.
            if (this.mode == KW || !this.encrypt) {
                int totalInput = Math.addExact(position, inLen);
                boolean unitBytesMultiple = (totalInput & (UNIT_BYTES - 1)) == 0;
                if (!unitBytesMultiple || (!this.encrypt && totalInput < UNIT_BYTES * 2)) {
                    throw new IllegalBlockSizeException("data should be at least 16 bytes and multiples of 8");
                }
            }

            // If decrypting in KWP mode, allocate a temporary bounce-buffer to receive the output.
            byte[] outBuf;
            int outBufOffset;
            if (!this.encrypt && this.mode == KWP) {
                // Since OpenSSL's KWP unwrap failure cleanup can write up to one unit beyond the documented
                // plaintext maximum, use an internal guarded buffer with one-unit (8-byte) guard space when
                // doing KWP decrypt.
                outputBounceBuffer = new byte[outputSize + UNIT_BYTES];

                // Output to the output bounce-buffer.
                outBuf = outputBounceBuffer;
                outBufOffset = 0;
            } else {
                // Output directly to the application-supplied output buffer.
                outBuf = out;
                outBufOffset = outOffset;
            }

            // If there is some data buffered in this.state.inputBuffer then use that buffer as the source
            // and move any additional input data to this.state.inputBuffer.
            // In addition, if the output bounce-buffer is not being used and the input and output application
            // buffers overlap but don't start at the same offset, then move all input to this.state.inputBuffer.
            if (position > 0 ||
                    (inLen > 0 && isOverlapping(input, inOffset, inLen, outBuf, outBufOffset, outputSize) && inOffset != outBufOffset)) {
                if (inLen > 0) {
                    // Move input data to this.state.inputBuffer.
                    appendToInputBuf(input, inOffset, inLen);
                }
                input = this.state.inputBuffer.array();
                inOffset = this.state.inputBuffer.arrayOffset();
                inLen = this.state.inputBuffer.position();
            }

            int outLen = ctx.update(input, inOffset, inLen, outBuf, outBufOffset);
            // Note that while it looks like OpenSSL does not require EVP_CipherFinal_ex to be called
            // for id-aes-wrap and id-aes-wrap-pad, we call it anyway.
            outLen += ctx.doFinal(outBuf, outBufOffset + outLen);
            if (outLen > outBuf.length - outBufOffset) {
                throw new AssertionError("Internal error: buffer overrun");
            }
            if (outputBounceBuffer != null) {
                if (outLen > out.length - outOffset) {
                    // The supplied buffer is not large enough to receive all the plaintext.

                    // Avoid calling cleanup() so that the restored state is available for a retry.
                    doCleanup = false;

                    if (position > 0) {
                        // Restore the position in inputBuffer to allow a retry of the doFinal() call with a larger
                        // output buffer.
                        this.state.inputBuffer.position(position);
                    }
                    throw new ShortBufferException("Not enough space in output array");
                }
                System.arraycopy(outputBounceBuffer, 0, out, outOffset, outLen);
            }
            return outLen;
        } catch (OpenSslException e) {
            if (this.encrypt) {
                IllegalBlockSizeException ibse = new IllegalBlockSizeException(e.getMessage());
                ibse.initCause(e.getCause());
                throw ibse;
            } else {
                BadPaddingException bpe = new BadPaddingException(e.getMessage());
                bpe.initCause(e.getCause());
                throw bpe;
            }
        } finally {
            Util.clearArray(outputBounceBuffer);
            if (doCleanup) {
                cleanup();
            }
        }
    }

    @Override
    int getUpdateOutputSize(int inputLen) {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        int totalInput = Math.addExact(this.state != null ? this.state.inputBuffer.position() : 0, inputLen);
        boolean unitBytesMultiple = (totalInput & (UNIT_BYTES - 1)) == 0;
        if (this.encrypt) {
            // Encrypt. For KW the input must be a multiple of UNIT_BYTES.
            return unitBytesMultiple || this.mode == KWP ? (totalInput + UNIT_BYTES * 2 - 1) & -UNIT_BYTES : 0;
        } else {
            // Decrypt. For both KW and KWP the input must be a multiple of UNIT_BYTES and be at least two units in size.
            return unitBytesMultiple && totalInput >= UNIT_BYTES * 2 ? totalInput - UNIT_BYTES : 0;
        }
    }

    @Override
    String getAlgorithmParametersAlg() {
        throw new UnsupportedOperationException();
    }

    @Override
    AlgorithmParameterSpec getParamSpec(byte[] iv, AlgorithmParameterSpec spec) {
        return null;
    }

    @Override
    byte[] verifyParams(AlgorithmParameterSpec params, boolean encrypt) throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("Parameters not expected for key wrap cipher");
        }
        return null;
    }

    @Override
    Class<? extends AlgorithmParameterSpec> getParameterSpecClass() {
        throw new UnsupportedOperationException();
    }

    @Override
    void cleanup() {
        this.updateCalled = false;
        this.state = null;
        if (this.cleanable != null) {
            this.cleanable.clean();
        }
        this.cleanable = null;
    }

    public static class AesWrap extends WrapCipher {
        public AesWrap() {
            super(new CipherAlg.AesKeyWrap(), KW);
        }
    }
    public static class AesWrap128 extends WrapCipher {
        public AesWrap128() {
            super(new CipherAlg.AesKeyWrap(128), KW);
        }
    }
    public static class AesWrap192 extends WrapCipher {
        public AesWrap192() {
            super(new CipherAlg.AesKeyWrap(192), KW);
        }
    }
    public static class AesWrap256 extends WrapCipher {
        public AesWrap256() {
            super(new CipherAlg.AesKeyWrap(256), KW);
        }
    }

    public static class AesWrapPad extends WrapCipher {
        public AesWrapPad() {
            super(new CipherAlg.AesKeyWrap(), KWP);
        }
    }
    public static class AesWrapPad128 extends WrapCipher {
        public AesWrapPad128() {
            super(new CipherAlg.AesKeyWrap(128), KWP);
        }
    }
    public static class AesWrapPad192 extends WrapCipher {
        public AesWrapPad192() {
            super(new CipherAlg.AesKeyWrap(192), KWP);
        }
    }
    public static class AesWrapPad256 extends WrapCipher {
        public AesWrapPad256() {
            super(new CipherAlg.AesKeyWrap(256), KWP);
        }
    }
}
