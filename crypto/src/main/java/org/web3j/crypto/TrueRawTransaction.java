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

    private String payment;//代付者账户
    private BigInteger fee;//发送者的扣费数量

    protected TrueRawTransaction(BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String to,
                                 BigInteger value, String data, BigInteger fee, String payment) {
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

    public TrueRawTransaction(SignedTrueRawTransaction signedTrueRawTransaction) {
        this.nonce = signedTrueRawTransaction.getNonce();
        this.gasPrice = signedTrueRawTransaction.getGasPrice();
        this.gasLimit = signedTrueRawTransaction.getGasLimit();
        this.to = signedTrueRawTransaction.getTo();
        this.value = signedTrueRawTransaction.getValue();

        this.fee = signedTrueRawTransaction.getFee();
        this.payment = signedTrueRawTransaction.getPayment();

        if (signedTrueRawTransaction.getData() != null) {
            this.data = Numeric.cleanHexPrefix(signedTrueRawTransaction.getData());
        }
    }

    public static TrueRawTransaction createContractTransaction(
            BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, BigInteger value,
            String init, BigInteger fee, String payment) {

        return new TrueRawTransaction(nonce, gasPrice, gasLimit, "", value, init, fee, payment);
    }

    public static TrueRawTransaction createEtherTransaction(
            BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String to,
            BigInteger value, BigInteger fee, String payment) {

        return new TrueRawTransaction(nonce, gasPrice, gasLimit, to, value, "", fee, payment);

    }

    public static TrueRawTransaction createTransaction(
            BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String to, String data, BigInteger fee, String payment) {
        return createTransaction(nonce, gasPrice, gasLimit, to, BigInteger.ZERO, data, fee, payment);
    }

    public static TrueRawTransaction createTransaction(
            BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String to,
            BigInteger value, String data, BigInteger fee, String payment) {

        return new TrueRawTransaction(nonce, gasPrice, gasLimit, to, value, data, fee, payment);
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

    public BigInteger getFee() {
        return fee;
    }

    public String getPayment() {
        return payment;
    }

}
