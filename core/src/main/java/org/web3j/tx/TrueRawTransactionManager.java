package org.web3j.tx;

import org.web3j.crypto.*;
import org.web3j.crypto.Sign.SignatureData;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTrueTransaction;
import org.web3j.tx.exceptions.TxHashMismatchException;
import org.web3j.tx.response.TransactionReceiptProcessor;
import org.web3j.utils.Numeric;
import org.web3j.utils.TxHashVerifier;

import java.io.IOException;
import java.math.BigInteger;

/**
 * TransactionManager implementation using Ethereum wallet file to create and sign transactions
 * locally.
 *
 * <p>This transaction manager provides support for specifying the chain id for transactions as per
 * <a href="https://github.com/ethereum/EIPs/issues/155">EIP155</a>, as well as for locally signing
 * RawTransaction instances without broadcasting them.
 */
public class TrueRawTransactionManager extends TrueTransactionManager {

    private final Web3j web3j;
    final Credentials credentials;

    static int chainId;

    protected TxHashVerifier txHashVerifier = new TxHashVerifier();

    public TrueRawTransactionManager(Web3j web3j, Credentials credentials, byte chainId) {
        super(web3j, credentials.getAddress());

        this.web3j = web3j;
        this.credentials = credentials;

        this.chainId = chainId;
    }

    public TrueRawTransactionManager(
            Web3j web3j, Credentials credentials, byte chainId,
            TransactionReceiptProcessor transactionReceiptProcessor) {
        super(transactionReceiptProcessor, credentials.getAddress());

        this.web3j = web3j;
        this.credentials = credentials;

        this.chainId = chainId;
    }

    public TrueRawTransactionManager(
            Web3j web3j, Credentials credentials, byte chainId, int attempts, long sleepDuration) {
        super(web3j, attempts, sleepDuration, credentials.getAddress());

        this.web3j = web3j;
        this.credentials = credentials;

        this.chainId = chainId;
    }

    public TrueRawTransactionManager(Web3j web3j, Credentials credentials) {
        this(web3j, credentials, ChainId.NONE);
    }

    public TrueRawTransactionManager(
            Web3j web3j, Credentials credentials, int attempts, int sleepDuration) {
        this(web3j, credentials, ChainId.NONE, attempts, sleepDuration);
    }

    protected BigInteger getNonce() throws IOException {
        EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(
                credentials.getAddress(), DefaultBlockParameterName.PENDING).send();

        return ethGetTransactionCount.getTransactionCount();
    }

    public TxHashVerifier getTxHashVerifier() {
        return txHashVerifier;
    }

    public void setTxHashVerifier(TxHashVerifier txHashVerifier) {
        this.txHashVerifier = txHashVerifier;
    }

    @Override
    public EthSendTrueTransaction sendTrueTransaction(
            BigInteger gasPrice, BigInteger gasLimit, String to,
            String data, BigInteger value, BigInteger fee, String payment) throws IOException {

        BigInteger nonce = getNonce();

        TrueRawTransaction trueRawTransaction = TrueRawTransaction.createTransaction(
                nonce,
                gasPrice,
                gasLimit,
                to,
                value,
                data,
                fee,
                payment);

        return signAndSend(trueRawTransaction);
    }

    /*
     * @param rawTransaction a RawTransaction istance to be signed
     * @return The transaction signed and encoded without ever broadcasting it
     */
    public String sign(TrueRawTransaction trueRawTransaction) {

        byte[] signedMessage;

        if (chainId > ChainId.NONE) {
            signedMessage = TrueTransactionEncoder.signMessage(trueRawTransaction, chainId, credentials);
        } else {
            signedMessage = TrueTransactionEncoder.signMessage(trueRawTransaction, credentials);
        }

        return Numeric.toHexString(signedMessage);
    }

    public EthSendTrueTransaction signAndSend(TrueRawTransaction trueRawTransaction)
            throws IOException {
        String hexValue = sign(trueRawTransaction);
        EthSendTrueTransaction ethSendTrueTransaction = web3j.ethSendTrueRawTransaction(hexValue).send();

        if (ethSendTrueTransaction != null && !ethSendTrueTransaction.hasError()) {
            String txHashLocal = Hash.sha3(hexValue);
            String txHashRemote = ethSendTrueTransaction.getTransactionHash();
            if (!txHashVerifier.verify(txHashLocal, txHashRemote)) {
                throw new TxHashMismatchException(txHashLocal, txHashRemote);
            }
        }

        return ethSendTrueTransaction;
    }

    //代付者签名接口
    public String sign_payment(TrueRawTransaction trueRawTransaction, Sign.SignatureData eip155SignatureData, long chainId, Credentials credentials_payment) {

        byte[] signedMessage;

        signedMessage = TrueTransactionEncoder.signMessage_payment(trueRawTransaction, eip155SignatureData,
                chainId, credentials_payment);

        return Numeric.toHexString(signedMessage);
    }

    //针对发送者已签名，需要代付者签名调用的接口
    public EthSendTrueTransaction signAndSend_payment(TrueRawTransaction trueRawTransaction, Sign.SignatureData eip155SignatureData, long chainId, Credentials credentials_payment)
            throws IOException {
        String hexValue = sign_payment(trueRawTransaction, eip155SignatureData, chainId, credentials_payment);

        EthSendTrueTransaction ethSendTrueTransaction = web3j.ethSendTrueRawTransaction(hexValue).send();

        if (ethSendTrueTransaction != null && !ethSendTrueTransaction.hasError()) {
            String txHashLocal = Hash.sha3(hexValue);
            String txHashRemote = ethSendTrueTransaction.getTransactionHash();
            if (!txHashVerifier.verify(txHashLocal, txHashRemote)) {
                throw new TxHashMismatchException(txHashLocal, txHashRemote);
            }
        }
        return ethSendTrueTransaction;
    }

}
