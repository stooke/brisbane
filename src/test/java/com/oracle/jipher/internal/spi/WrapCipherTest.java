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

import java.util.Arrays;
import javax.crypto.BadPaddingException;

import org.junit.Test;

import com.oracle.jipher.internal.openssl.CipherCtx;
import com.oracle.jipher.internal.openssl.OpenSslException;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class WrapCipherTest {

    @Test
    public void kwpUnwrapGuardedInternalBuffer() throws Exception {
        WrapCipher cipher = new WrapCipher.AesWrapPad();
        CipherCtx ctx = mock(CipherCtx.class);

        cipher.ctx = ctx;
        cipher.initialized = true;
        cipher.encrypt = false;

        // Handle to retain buffer captured in closure
        final byte[][] capturedOutBuffer = new byte[1][];

        // Set just a few of the bytes to allow both that these are set and that the remaining bytes is retained
        when(ctx.update(any(), anyInt(), anyInt(), any(), anyInt())).thenAnswer(invocation -> {
            byte[] outBuf = invocation.getArgument(3);
            int outOffset = invocation.getArgument(4);
            capturedOutBuffer[0] = outBuf;
            outBuf[outOffset] = 1;
            outBuf[outOffset + 1] = 2;
            return 2;
        });
        when(ctx.doFinal(any(), anyInt())).thenReturn(0);

        byte[] in = new byte[16];
        byte[] out = new byte[8];
        Arrays.fill(out, (byte) 0x55);

        int outLen = cipher.engineDoFinal(in, 0, in.length, out, 0);

        // Check that the bytes expected to be set are the expected values
        assertEquals(2, outLen);
        assertArrayEquals(new byte[]{1, 2}, Arrays.copyOf(out, outLen));

        // Check that the remaining buffer is retained
        assertEquals((byte) 0x55, out[outLen]);

        // Check that the bounce buffer in KWP unwrap is different to the passed in out buffer
        assertNotSame(out, capturedOutBuffer[0]);

        // Check that the bounce buffer in KWP unwrap is the actual out buffer size 8 + 8-byte guard
        assertEquals(16, capturedOutBuffer[0].length);

        // Check that the bounce buffer is a new, cleared buffer (relying on implicit zeroization of buffers)
        assertArrayEquals(capturedOutBuffer[0], new byte[capturedOutBuffer[0].length]);
    }

    @Test
    public void kwpUnwrapErrorLeavesOutputUnchanged() throws Exception {
        WrapCipher cipher = new WrapCipher.AesWrapPad();
        CipherCtx ctx = mock(CipherCtx.class);

        cipher.ctx = ctx;
        cipher.initialized = true;
        cipher.encrypt = false;

        when(ctx.update(any(), anyInt(), anyInt(), any(), anyInt())).thenAnswer(invocation -> {
            byte[] outBuf = invocation.getArgument(3);
            int outOffset = invocation.getArgument(4);
            // Fill buffer with something entirely different
            Arrays.fill(outBuf, outOffset, outOffset + 16, (byte) 0xAA);
            return 2;
        });
        when(ctx.doFinal(any(), anyInt())).thenThrow(new OpenSslException("forced error"));

        byte[] in = new byte[16];
        byte[] out = new byte[16];
        Arrays.fill(out, (byte) 0x55);
        byte[] expectedOut = out.clone();

        try {
            cipher.engineDoFinal(in, 0, in.length, out, 0);
            fail("Expected engineDoFinal to fail and throw BadPaddingException");
        } catch (BadPaddingException expected) {
            // Ensure the caller's output buffer is unchanged after BadPaddingException.
            assertArrayEquals(expectedOut, out);
        }
    }

}
