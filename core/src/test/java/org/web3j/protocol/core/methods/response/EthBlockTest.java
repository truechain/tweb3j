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
package org.web3j.protocol.core.methods.response;

import java.math.BigInteger;

import org.junit.Test;

import static junit.framework.TestCase.assertEquals;

public class EthBlockTest {

    @Test
    public void testEthBlockNullSize() {
        EthBlock.Block ethBlock =
                new EthBlock.Block(
                        null, null, null, null, null, null, null, null, null, null, null, null,
                        null, null, null, null, null, null, null, null, null, null);

        assertEquals(ethBlock.getSize(), BigInteger.ZERO);
    }

    @Test
    public void testEthBlockNotNullSize() {
        EthBlock.Block ethBlock =
                new EthBlock.Block(
                        null, null, null, null, null, null, null, null, null, null, null, null,
                        null, null, null, "0x3e8", null, null, null, null, null, null);

        assertEquals(ethBlock.getSize(), BigInteger.valueOf(1000));
    }
}
