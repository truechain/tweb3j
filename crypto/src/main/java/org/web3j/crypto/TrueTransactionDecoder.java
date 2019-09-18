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

import org.web3j.rlp.RlpDecoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.utils.Numeric;

import java.math.BigInteger;

public class TrueTransactionDecoder {

    public static TrueRawTransaction decode(final String hexTransaction) {
        final byte[] transaction = Numeric.hexStringToByteArray(hexTransaction);
        final RlpList rlpList = RlpDecoder.decode(transaction);
        final RlpList values = (RlpList) rlpList.getValues().get(0);
        final BigInteger nonce = ((RlpString) values.getValues().get(0)).asPositiveBigInteger();
        final BigInteger gasPrice = ((RlpString) values.getValues().get(1)).asPositiveBigInteger();
        final BigInteger gasLimit = ((RlpString) values.getValues().get(2)).asPositiveBigInteger();
        final String to = ((RlpString) values.getValues().get(3)).asString();
        final BigInteger value = ((RlpString) values.getValues().get(4)).asPositiveBigInteger();
        final String data = ((RlpString) values.getValues().get(5)).asString();

        final String payment = ((RlpString) values.getValues().get(6)).asString();
        final BigInteger fee = ((RlpString) values.getValues().get(7)).asPositiveBigInteger();

        if (values.getValues().size() == 8
                || (values.getValues().size() == 10
                        && ((RlpString) values.getValues().get(9)).getBytes().length == 12)
                || (values.getValues().size() == 11
                        && ((RlpString) values.getValues().get(10)).getBytes().length == 12)) {
            // the 8th or 9nth element is the hex
            // representation of "restricted" for private transactions
            return TrueRawTransaction.createTransaction(nonce, gasPrice, gasLimit, to, value, data,fee,payment);
        } else {
            final byte[] v = ((RlpString) values.getValues().get(8)).getBytes();
            final byte[] r =
                    Numeric.toBytesPadded(
                            Numeric.toBigInt(((RlpString) values.getValues().get(9)).getBytes()),
                            32);
            final byte[] s =
                    Numeric.toBytesPadded(
                            Numeric.toBigInt(((RlpString) values.getValues().get(10)).getBytes()),
                            32);
            final Sign.SignatureData signatureData = new Sign.SignatureData(v, r, s);
            return new SignedTrueRawTransaction(
                    nonce, gasPrice, gasLimit, to, value, data,fee,payment ,signatureData);
        }
    }
}
