package org.web3j.protocol.core.methods.response;

import java.math.BigInteger;

import org.web3j.protocol.core.Response;
import org.web3j.utils.Numeric;

/**
 * eth_True_blockNumber.
 */
public class ETrueBlockNumber extends Response<String> {
    public BigInteger getTrueBlockNumber() {
        return Numeric.decodeQuantity(getResult());
    }
}
