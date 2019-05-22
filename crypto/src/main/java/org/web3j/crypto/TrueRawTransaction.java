package org.web3j.crypto;

import java.math.BigInteger;

import org.web3j.utils.Numeric;

/**
 * Transaction class used for signing transactions locally.<br>
 * For the specification, refer to p4 of the <a href="http://gavwood.com/paper.pdf">
 * yellow paper</a>.
 */
public class TrueRawTransaction {

    private BigInteger nonce;
    private BigInteger gasPrice;
    private BigInteger gasLimit;
    private String to;
    private BigInteger value;
    private String data;
    
    private String fee;
    private String payment;
    
    protected TrueRawTransaction(BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String to,
                           BigInteger value, String data, String fee, String payment) {
        this.nonce = nonce;
        this.gasPrice = gasPrice;
        this.gasLimit = gasLimit;
        this.to = to;
        this.value = value;
        
        this.fee = fee;
        this.payment = payment;

        if (data != null) {
            this.data = Numeric.cleanHexPrefix(data);
        }
    }

    public static TrueRawTransaction createContractTransaction(
            BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, BigInteger value,
            String init, String fee, String payment) {

        return new TrueRawTransaction(nonce, gasPrice, gasLimit, "", value, init,fee,payment);
    }

    public static TrueRawTransaction createEtherTransaction(
            BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String to,
            BigInteger value, String fee, String payment) {

        return new TrueRawTransaction(nonce, gasPrice, gasLimit, to, value, "",fee,payment);

    }

    public static TrueRawTransaction createTransaction(
            BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String to, String data, String fee, String payment) {
        return createTransaction(nonce, gasPrice, gasLimit, to, BigInteger.ZERO, data,fee,payment);
    }

    public static TrueRawTransaction createTransaction(
            BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String to,
            BigInteger value, String data, String fee, String payment) {

        return new TrueRawTransaction(nonce, gasPrice, gasLimit, to, value, data,fee,payment);
    }

    public BigInteger getNonce() {
        return nonce;
    }

    public BigInteger getGasPrice() {
        return gasPrice;
    }

    public BigInteger getGasLimit() {
        return gasLimit;
    }

    public String getTo() {
        return to;
    }

    public BigInteger getValue() {
        return value;
    }

    public String getData() {
        return data;
    }

    public String getFee() {
        return fee;
    }

    public String getPayment() {
        return payment;
    }

}
