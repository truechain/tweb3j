package org.web3j.tx;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;

import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.crypto.TrueRawTransaction;
import org.web3j.crypto.TrueTransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.EthSendTrueTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.exceptions.TxHashMismatchException;
import org.web3j.tx.response.TransactionReceiptProcessor;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;
import org.web3j.utils.TxHashVerifier;

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

    static int chainId = 19330;

    protected TxHashVerifier txHashVerifier = new TxHashVerifier();

    public static void main(String[] args) throws InterruptedException, ExecutionException {
        
        try {
            Web3j web3jt = Web3j.build(new HttpService("https://rpc.truescan.net/testnet"));
             
            String toAddress = "0x092754c9b93ea1c15524f4be1c5f46af5ea68844";
            String contractAddress = "0x092754c9b93ea1c15524f4be1c5f46af5ea68844";
            
            Credentials credentials = Credentials.create("0x59ea68d5bfa801185b5cb0e32ec5b6364cb79cf9c2f74f589fd018ea2a84bd79");
            String fromAddress = credentials.getAddress();
            
            EthGetTransactionCount ethGetTransactionCount = web3jt
                    .ethGetTransactionCount(fromAddress, DefaultBlockParameterName.LATEST).sendAsync().get();
            BigInteger nonce = ethGetTransactionCount.getTransactionCount();
            
            Double transNum = Double.parseDouble("2000");
            Integer transNumInt = (int) (transNum * 100000000);
            
            BigInteger bi1 = new BigInteger(String.valueOf(transNumInt));
            BigInteger bi2 = new BigInteger("10000000000");
            BigInteger bi3 = bi1.multiply(bi2);

            Function function = new Function("transfer",
                    Arrays.asList(new Address(toAddress), new Uint256(bi3)),
                    Arrays.asList(new TypeReference<Type>() {}));
            String encodedFunction = FunctionEncoder.encode(function);
            
            TrueRawTransaction trueRawTransaction = TrueRawTransaction.createTransaction(
                nonce,
                Convert.toWei("18", Convert.Unit.GWEI).toBigInteger(), 
                Convert.toWei("100000", Convert.Unit.WEI).toBigInteger(), 
                contractAddress,
                new BigInteger("1000000000"),
                encodedFunction,
                "0x", 
                "0x092754c9b93ea1c15524f4be1c5f46af5ea68844");
            
            byte[] signedMessage = TrueTransactionEncoder.signMessage(trueRawTransaction, chainId, credentials);
            String hexValue = Numeric.toHexString(signedMessage);            
            System.out.println("=====hexValue=====:" + hexValue);
            //String hexValue = "0xf8c60183989680834c4b4094bea78fea68dba84363d0f9b79219ddf5991ccb2a880de0b6b3a76400008094cfb7ec3ac64a3afde043a5b32212d0b9c25b5d808081eba07cc4b8300a8ab6a7d6aee713f6dc61311848bf827794c370873ca334e7cc2cc1a05cd365ffc46cada820911e3c11123e36245ed1cec7943038632715a89a421b0281eca037d6e60016bd70371fd45a2fadd63f8824b34331f2cb5f7fe69f04df7f6d9caea04e05dda8cffa3e453aa474f955eef97fe63e9c9721860aaea379a0ace111fd16";
            
            EthSendTrueTransaction ethSendTrueTransaction = web3jt.ethSendTrueRawTransaction(hexValue).send();
            if (ethSendTrueTransaction != null && !ethSendTrueTransaction.hasError()) {
                String txHashLocal = Hash.sha3(hexValue);
                String txHashRemote = ethSendTrueTransaction.getTransactionHash();
                
                System.out.println("txHashLocal:" + txHashLocal);
                System.out.println("txHashRemote:" + txHashRemote);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
    
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
            String data, BigInteger value, String fee, String payment) throws IOException {

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
}
