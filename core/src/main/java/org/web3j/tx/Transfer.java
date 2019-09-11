package org.web3j.tx;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.TrueRawTransaction;
import org.web3j.crypto.TrueTransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.RemoteCall;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTrueTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.exceptions.TransactionException;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

/**
 * Class for performing Ether transactions on the Ethereum blockchain.
 */
public class Transfer extends ManagedTransaction {
    //代付gas交易示例
    public static void main2(String[] args) throws InterruptedException, ExecutionException {
        try {
            Web3j web3jt = Web3j.build(new HttpService("http://127.0.0.1:8888"));
            String to = "0x04d2252a3e0ca7c2aa81247ca33060855a34a808";

            //代付者账户
            String payment = "0x4cf807958b9F6D9fD9331397d7a89a079ef43288";

            BigInteger value = Convert.toWei("1", Convert.Unit.ETHER).toBigInteger();
            //发送者的扣费数量 可为空
            BigInteger fee = Convert.toWei("1", Convert.Unit.ETHER).toBigInteger();
            BigInteger gaslimit = Convert.toWei("210000", Convert.Unit.WEI).toBigInteger();
            BigInteger gasprice = Convert.toWei("1", Convert.Unit.GWEI).toBigInteger();

            //发送者账户
            Credentials credentials = Credentials.create(
                    "0x647EEEB80193A47A02D31939AF29EFA006DBE6DB45C8806AF764C18B262BB90B");
            String fromAddress = credentials.getAddress();
            System.out.println("fromAddress:" + fromAddress);

            //代付者账户
            Credentials credentials_payment = Credentials.create("0x06E95F58760688B722261B96E2B13BBE9A0E0F7B4541513E156A16B7D6CE1BAF");

            EthGetTransactionCount ethGetTransactionCount = web3jt
                    .ethGetTransactionCount(fromAddress, DefaultBlockParameterName.LATEST).sendAsync().get();
            BigInteger nonce = ethGetTransactionCount.getTransactionCount();
            long chainId = 400;

            TrueRawTransaction trueRawTransaction = TrueRawTransaction.createTransaction(
                    nonce,
                    gasprice,
                    gaslimit,
                    to,
                    value,
                    "",
                    fee,
                    payment);

            byte[] signedMessage = TrueTransactionEncoder.signMessage_fromAndPayment(trueRawTransaction, chainId, credentials, credentials_payment);
            String hexValue = Numeric.toHexString(signedMessage);

            EthSendTrueTransaction ethSendTrueTransaction = web3jt.ethSendTrueRawTransaction(hexValue).send();
            if (ethSendTrueTransaction != null && !ethSendTrueTransaction.hasError()) {
                String txHashLocal = Hash.sha3(hexValue);
                String txHashRemote = ethSendTrueTransaction.getTransactionHash();

                System.out.println(" txHashLocal--->" + txHashLocal);
                System.out.println("txHashRemote--->" + txHashRemote);
                //......
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //普通转账示例
    public static void main(String[] args) {
        // http://39.98.43.179:8888
        // https://rpc.truescan.net/testnet
        // Web3j web3j = Web3j.build(new
        // HttpService("https://rpc.truescan.net/testnet"));
        Web3j web3j = Web3j.build(new HttpService("http://127.0.0.1:8888"));
//        String toAddress = "0x04d2252a3e0ca7c2aa81247ca33060855a34a808";
        String toAddress = "0x4cf807958b9f6d9fd9331397d7a89a079ef43288";


        Credentials credentials = Credentials.create("0x647EEEB80193A47A02D31939AF29EFA006DBE6DB45C8806AF764C18B262BB90B");
        int chainId = 400;

        try {
            TransactionReceipt transactionReceipt = Transfer
                    .sendFunds(web3j, credentials, toAddress, new BigDecimal("1"), Convert.Unit.ETHER, chainId).send();

            String transactionHash = transactionReceipt.getTransactionHash();
            System.out.println("transactionHash------------------->" + transactionHash);
        } catch (TransactionException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // This is the cost to send Ether between parties
    public static final BigInteger GAS_LIMIT = BigInteger.valueOf(21000);

    public Transfer(Web3j web3j, TransactionManager transactionManager) {
        super(web3j, transactionManager);
    }

    /**
     * Given the duration required to execute a transaction, asyncronous execution
     * is strongly recommended via
     * {@link Transfer#sendFunds(String, BigDecimal, Convert.Unit)}.
     *
     * @param toAddress destination address
     * @param value     amount to send
     * @param unit      of specified send
     * @return {@link Optional} containing our transaction receipt
     * @throws ExecutionException   if the computation threw an exception
     * @throws InterruptedException if the current thread was interrupted while waiting
     * @throws TransactionException if the transaction was not mined while waiting
     */
    private TransactionReceipt send(String toAddress, BigDecimal value, Convert.Unit unit)
            throws IOException, InterruptedException, TransactionException {

        BigInteger gasPrice = requestCurrentGasPrice();
        return send(toAddress, value, unit, gasPrice, GAS_LIMIT);
    }

    private TransactionReceipt send(String toAddress, BigDecimal value, Convert.Unit unit, BigInteger gasPrice,
                                    BigInteger gasLimit) throws IOException, InterruptedException, TransactionException {

        BigDecimal weiValue = Convert.toWei(value, unit);
        if (!Numeric.isIntegerValue(weiValue)) {
            throw new UnsupportedOperationException(
                    "Non decimal Wei value provided: " + value + " " + unit.toString() + " = " + weiValue + " Wei");
        }

        String resolvedAddress = ensResolver.resolve(toAddress);
        return send(resolvedAddress, "", weiValue.toBigIntegerExact(), gasPrice, gasLimit);
    }

    public static RemoteCall<TransactionReceipt> sendFunds(Web3j web3j, Credentials credentials, String toAddress,
                                                           BigDecimal value, Convert.Unit unit, int chainId)
            throws InterruptedException, IOException, TransactionException {

        TransactionManager transactionManager = new RawTransactionManager(web3j, credentials);

        return new RemoteCall<>(() -> new Transfer(web3j, transactionManager).send(toAddress, value, unit));
    }

    /**
     * Execute the provided function as a transaction asynchronously. This is
     * intended for one-off fund transfers. For multiple, create an instance.
     *
     * @param toAddress destination address
     * @param value     amount to send
     * @param unit      of specified send
     * @return {@link RemoteCall} containing executing transaction
     */
    public RemoteCall<TransactionReceipt> sendFunds(String toAddress, BigDecimal value, Convert.Unit unit) {
        return new RemoteCall<>(() -> send(toAddress, value, unit));
    }

    public RemoteCall<TransactionReceipt> sendFunds(String toAddress, BigDecimal value, Convert.Unit unit,
                                                    BigInteger gasPrice, BigInteger gasLimit) {
        return new RemoteCall<>(() -> send(toAddress, value, unit, gasPrice, gasLimit));
    }
}
