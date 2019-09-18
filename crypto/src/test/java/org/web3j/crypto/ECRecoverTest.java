/*
 * Copyright 2019 Web3 Labs LTD.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.web3j.crypto;

import java.math.BigInteger;
import java.util.Arrays;

import org.junit.Test;

import org.web3j.crypto.Sign.SignatureData;
import org.web3j.utils.Numeric;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class ECRecoverTest {

    public static final String PERSONAL_MESSAGE_PREFIX = "\u0019Ethereum Signed Message:\n";

    @Test
    public void testRecoverAddressFromSignature() {

        String signature =
                "0x2c6401216c9031b9a6fb8cbfccab4fcec6c951cdf40e2320108d1856eb532250576865fbcd452bcdc4c57321b619ed7a9cfd38bd973c3e1e0243ac2777fe9d5b1b";

        String address = "0x31b26e43651e9371c88af3d36c14cfd938baf4fd";
        String message = "v0G9u7huK4mJb2K1";

        String prefix = PERSONAL_MESSAGE_PREFIX + message.length();
        byte[] msgHash = Hash.sha3((prefix + message).getBytes());

        byte[] signatureBytes = Numeric.hexStringToByteArray(signature);
        byte v = signatureBytes[64];
        if (v < 27) {
            v += 27;
        }

        SignatureData sd =
                new SignatureData(
                        v,
                        (byte[]) Arrays.copyOfRange(signatureBytes, 0, 32),
                        (byte[]) Arrays.copyOfRange(signatureBytes, 32, 64));


        String addressRecovered = null;
        boolean match = false;

        // Iterate for each possible key to recover
        for (int i = 0; i < 4; i++) {
            BigInteger publicKey =
                    Sign.recoverFromSignature(
                            (byte) i,
                            new ECDSASignature(
                                    new BigInteger(1, sd.getR()), new BigInteger(1, sd.getS())),
                            msgHash);

            if (publicKey != null) {
                addressRecovered = "0x" + Keys.getAddress(publicKey);

                if (addressRecovered.equals(address)) {
                    match = true;
                    break;
                }
            }
        }

        assertThat(addressRecovered, is(address));
        assertTrue(match);
    }

    @Test
    public void testRecoverAddressFromSignature2() {

        String address = "0xa23Bd55b0f3559a92823b5b50b5f02ed6E58364B";

        byte[] msgHash = Numeric.hexStringToByteArray("0xbf487a7950961bf424813a1731c7faada17567781c5545583c11c13a38235f20");

        //接收前端传入的v，r，s来直接操作
        long v =Long.parseLong("9403", 16)-2*18928-8;

        byte[] r = Numeric.hexStringToByteArray("0xeefaf02106e8e72bf99342894d8d2a6d019c73094023300beca885bff9840630");
        byte[] s = Numeric.hexStringToByteArray("0x533f6a4bc1f484e2c188c58d2f6156c9a7e30bba6f2c005898f501e037cdb9");
        Sign.SignatureData sd = new Sign.SignatureData((byte)(27), r, s);


        String addressRecovered = null;
        boolean match = false;

        // Iterate for each possible key to recover
        for (int i = 0; i < 4; i++) {
            BigInteger publicKey =
                    Sign.recoverFromSignature(
                            (byte) i,
                            new ECDSASignature(
                                    new BigInteger(1, sd.getR()), new BigInteger(1, sd.getS())),
                            msgHash);

            if (publicKey != null) {
                addressRecovered = "0x" + Keys.getAddress(publicKey);

                if (addressRecovered.equals(address)) {
                    match = true;
                    break;
                }
            }
        }

        assertThat(addressRecovered, is(address));
        assertTrue(match);
    }
}
