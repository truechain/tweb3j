package org.web3j.tx;


import org.web3j.crypto.*;
import org.web3j.crypto.TrueTransactionDecoder;
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
import java.util.Arrays;
/**
 * Class for performing Ether transactions on the Ethereum blockchain.
 */
public class Transfer extends ManagedTransaction {

    public static void main_111(String[] args) throws InterruptedException, ExecutionException {
//        byte[] s =new BigInteger("38298").toByteArray();
//        for (byte b:s){
//            System.out.println(b);
//        }

    }

    //发送者和代付依次签名使用和测试示例
    public static void main66(String[] args) throws InterruptedException, ExecutionException {
        try {
//            Web3j web3jt = Web3j.build(new HttpService("http://127.0.0.1:8888"));
            Web3j web3jt = Web3j.build(new HttpService("https://rpc.truescan.net/testnet"));


            //发送者账户
//            Credentials credentials_from = Credentials.create(
//                    "0x647EEEB80193A47A02D31939AF29EFA006DBE6DB45C8806AF764C18B262BB90B");
//            String fromAddress = credentials.getAddress();
//            System.out.println("fromAddress:" + fromAddress);
//
//            //代付者账户
//            String payment = "0x4cf807958b9F6D9fD9331397d7a89a079ef43288";
//            Credentials credentials_payment = Credentials.create("0x06E95F58760688B722261B96E2B13BBE9A0E0F7B4541513E156A16B7D6CE1BAF");


            //发送者账户
            String fromAddress = "0xa23Bd55b0f3559a92823b5b50b5f02ed6E58364B";
            Credentials credentials_from = Credentials.create("0xA7EDEABF6E01370721CBA7B0FF885C0B05AEF818CE93869A445FE0EA185F5662");
            //代付者账户
//            String payment = "0x3dd442d92e887700f61b0d29aa73094ecedde7a1";
//            Credentials credentials_payment = Credentials.create("0x123321");

            String payment = "0xa23Bd55b0f3559a92823b5b50b5f02ed6E58364B";
            Credentials credentials_payment = Credentials.create("0xA7EDEABF6E01370721CBA7B0FF885C0B05AEF818CE93869A445FE0EA185F5662");


            String to = "0x04d2252a3e0ca7c2aa81247ca33060855a34a808";

            BigInteger value = Convert.toWei("1", Convert.Unit.ETHER).toBigInteger();
            //发送者的扣费数量 可为空
            BigInteger fee = Convert.toWei("1", Convert.Unit.ETHER).toBigInteger();
            BigInteger gaslimit = Convert.toWei("210000", Convert.Unit.WEI).toBigInteger();
            BigInteger gasprice = Convert.toWei("1", Convert.Unit.GWEI).toBigInteger();

            EthGetTransactionCount ethGetTransactionCount = web3jt
                    .ethGetTransactionCount(fromAddress, DefaultBlockParameterName.LATEST).sendAsync().get();
            BigInteger nonce = ethGetTransactionCount.getTransactionCount();
            long chainId = 18928;

            TrueRawTransaction trueRawTransaction = TrueRawTransaction.createTransaction(
                    nonce,
                    gasprice,
                    gaslimit,
                    to,
                    value,
                    "",
                    fee,
                    payment);

            byte[] signedMessage = TrueTransactionEncoder.signMessage_fromAndPayment(trueRawTransaction, chainId, credentials_from, credentials_payment);
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

    //
    public static void main_old(String[] args) throws Exception {
        try {
            String url ="http://127.0.0.1:8888";//"https://rpc.truescan.net/testnet"
            int CHAINID =18928;
            Web3j web3jt = Web3j.build(new HttpService(url));

            int chainId = CHAINID;
//            curl http://39.98.214.253:8888 -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"etrue_blockNumber","params":[],"id":100}'
//            curl http://172.26.73.80:8888 -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"etrue_blockNumber","params":[],"id":100}'
            //发送者的扣费数量 可为空
            BigInteger fee = Convert.toWei("1", Convert.Unit.ETHER).toBigInteger();
            BigInteger gaslimit = Convert.toWei("210000", Convert.Unit.WEI).toBigInteger();
            BigInteger gasprice = Convert.toWei("1", Convert.Unit.GWEI).toBigInteger();
            BigInteger value = Convert.toWei("1", Convert.Unit.ETHER).toBigInteger();

            String to = "ebc52d9081F795d094491a61C7927A74b03eb71F";
            //发送者账户
            String fromAddress = "0xa23Bd55b0f3559a92823b5b50b5f02ed6E58364B";
            Credentials credentials_from = Credentials.create("0xA7EDEABF6E01370721CBA7B0FF885C0B05AEF818CE93869A445FE0EA185F5662");

            //代付者账户
//            String payment = "0x3dd442d92e887700f61b0d29aa73094ecedde7a1";
            String payment = "0xa23Bd55b0f3559a92823b5b50b5f02ed6E58364B";
//            Credentials credentials_payment = Credentials.create("0x123321");
            Credentials credentials_payment = Credentials.create("0xA7EDEABF6E01370721CBA7B0FF885C0B05AEF818CE93869A445FE0EA185F5662");


            EthGetTransactionCount ethGetTransactionCount = web3jt
                    .ethGetTransactionCount(fromAddress, DefaultBlockParameterName.LATEST).sendAsync().get();
            BigInteger nonce = ethGetTransactionCount.getTransactionCount();
            //            long chainId = 18928;

            TrueRawTransaction trueRawTransaction = TrueRawTransaction.createTransaction(
                    nonce,
                    gasprice,
                    gaslimit,
                    to,
                    value,
                    "",
                    fee,
                    payment);

            byte[] encodedTransaction = TrueTransactionEncoder.encode(trueRawTransaction, chainId);
            Sign.SignatureData signatureData = Sign.signMessage(encodedTransaction, credentials_from.getEcKeyPair());
            Sign.SignatureData eip155SignatureData = TrueTransactionEncoder.createEip155SignatureData(signatureData, chainId);

//            byte[] v = Numeric.hexStringToByteArray("0x9404");
//            byte[] r = Numeric.hexStringToByteArray("0xf79bd00522b6b26bcbbf1cba350a33ba1c8df8bc35493e960a3ad8296eca9f37");
//            byte[] s = Numeric.hexStringToByteArray("0x5d4c76385a8490668346b615f5c07cd2e1042f75dbcb0dafd7d47ac29840dd60");


//            Sign.SignatureData eip155SignatureData = new Sign.SignatureData(v, r, s);
//            System.out.println("eip155SignatureData=" + eip155SignatureData.getV().toString());
//            System.out.println("eip155SignatureData=" + eip155SignatureData.getR().toString());
//            System.out.println("eip155SignatureData=" + eip155SignatureData.getS().toString());

            byte[] signedMessage = TrueTransactionEncoder.signMessage_payment(trueRawTransaction, eip155SignatureData, chainId, credentials_payment);
            String hexValue = Numeric.toHexString(signedMessage);

            EthSendTrueTransaction ethSendTrueTransaction = web3jt.ethSendTrueRawTransaction(hexValue).send();



            String txHashLocal = Hash.sha3(hexValue);
            String txHashRemote = ethSendTrueTransaction.getTransactionHash();

            System.out.println(" txHashLocal--->" + txHashLocal);
            System.out.println("txHashRemote--->" + txHashRemote);
//            if (ethSendTrueTransaction != null && !ethSendTrueTransaction.hasError()) {
//                String txHashLocal = Hash.sha3(hexValue);
//                String txHashRemote = ethSendTrueTransaction.getTransactionHash();
//
//                System.out.println(" txHashLocal--->" + txHashLocal);
//                System.out.println("txHashRemote--->" + txHashRemote);
//            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    //代付者签名交易实例
    public static void main(String[] args) throws Exception {
        try {
            String url ="https://rpc.truescan.net/testnet";
//            String url ="http://127.0.0.1:8888";//
            Web3j web3jt = Web3j.build(new HttpService(url));

            int chainId = 18928;
//            curl http://39.98.214.253:8888 -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"etrue_blockNumber","params":[],"id":100}'
//            curl http://172.26.73.80:8888 -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"etrue_blockNumber","params":[],"id":100}'
            //发送者的扣费数量 可为空
            BigInteger fee = Convert.toWei("1", Convert.Unit.ETHER).toBigInteger();
            BigInteger gaslimit = Convert.toWei("210000", Convert.Unit.WEI).toBigInteger();
            BigInteger gasprice = Convert.toWei("1", Convert.Unit.GWEI).toBigInteger();
            BigInteger value = Convert.toWei("1", Convert.Unit.ETHER).toBigInteger();
            String to = "0xebc52d9081F795d094491a61C7927A74b03eb71F";

            //发送者账户
            String fromAddress = "0xa23Bd55b0f3559a92823b5b50b5f02ed6E58364B";
            Credentials credentials_from = Credentials.create("0xA7EDEABF6E01370721CBA7B0FF885C0B05AEF818CE93869A445FE0EA185F5662");
            //代付者账户
//            String payment = "0x3dd442d92e887700f61b0d29aa73094ecedde7a1";
//            Credentials credentials_payment = Credentials.create("0x123321");

            String payment = "0xa23Bd55b0f3559a92823b5b50b5f02ed6E58364B";
            Credentials credentials_payment = Credentials.create("0xA7EDEABF6E01370721CBA7B0FF885C0B05AEF818CE93869A445FE0EA185F5662");


            EthGetTransactionCount ethGetTransactionCount = web3jt
                    .ethGetTransactionCount(fromAddress, DefaultBlockParameterName.LATEST).sendAsync().get();
            BigInteger nonce = ethGetTransactionCount.getTransactionCount();

            TrueRawTransaction trueRawTransaction = TrueRawTransaction.createTransaction(
                    nonce,
                    gasprice,
                    gaslimit,
                    to,
                    value,
                    "",
                    fee,
                    payment);
            //本地生成的v，r，s
//            byte[] encodedTransaction = TrueTransactionEncoder.encode(trueRawTransaction, chainId);
//            System.out.println("local messageHash--->" + Arrays.toString(Hash.sha3(encodedTransaction)));
//            Sign.SignatureData signatureData = Sign.signMessage(encodedTransaction, credentials_from.getEcKeyPair());
//            Sign.SignatureData eip155SignatureData_local = TrueTransactionEncoder.createEip155SignatureData(signatureData, chainId);


            //通过接受到的hash来直接操作
//            byte[] encodedTransaction2 = Numeric.hexStringToByteArray("0xbf487a7950961bf424813a1731c7faada17567781c5545583c11c13a38235f20");
//            System.out.println("self messageHash--->" + Arrays.toString(encodedTransaction2));
//            Sign.SignatureData signatureData2 = Sign.signPrefixedMessage(encodedTransaction, credentials_from.getEcKeyPair());
//            Sign.SignatureData eip155SignatureData_local2 = TrueTransactionEncoder.createEip155SignatureData(signatureData, chainId);


            //通过rawTransaction解码出交易信息，包括发送者签名rsv
            String rawTransaction="0xf89382013d843b9aca008303345094ebc52d9081f795d094491a61c7927a74b03eb71f880de0b6b3a76400008094a23bd55b0f3559a92823b5b50b5f02ed6e58364b880de0b6b3a7640000829404a030877d1f64916ab6e73da4b5184012ed5fd86e03ec132b936a248e2f64f834eaa0163a621c8251416f9ed8bc807f628b5480dd00268667240187e13e985df46f2e8249f08080";
            SignedTrueRawTransaction signtrueRawTransaction = (SignedTrueRawTransaction)TrueTransactionDecoder.decode(rawTransaction);
            System.out.println(signtrueRawTransaction);
            Sign.SignatureData decode_signatureData=signtrueRawTransaction.getSignatureData();
            TrueRawTransaction decode_trueRawTransaction =new TrueRawTransaction(signtrueRawTransaction);
            System.out.println("decode messageHash--->" + Arrays.toString(Hash.sha3(TrueTransactionEncoder.encode(decode_trueRawTransaction, chainId))));


            //接收前端传入的v，r，s来直接操作
            byte[] v = Numeric.hexStringToByteArray("0x9403");//0f52d4e2c79ff092fe1cb08b345728925a1a88f5
            byte[] r = Numeric.hexStringToByteArray("0xbcbbfeaf0d101c426c2d442ab77f9f28cf78418c540b7d2eb6e53f2cdc69822a");
            byte[] s = Numeric.hexStringToByteArray("0x313a1274e3448b7b727c88cb06d33c5abecab801b7f07c858e921b32725f3732");
            Sign.SignatureData eip155SignatureData = new Sign.SignatureData(v, r, s);


//            byte[] signedMessage = TrueTransactionEncoder.signMessage_payment(trueRawTransaction, eip155SignatureData, chainId, credentials_payment);
            byte[] signedMessage = TrueTransactionEncoder.signMessage_payment(decode_trueRawTransaction, decode_signatureData, chainId, credentials_payment);
            String hexValue = Numeric.toHexString(signedMessage);
            EthSendTrueTransaction ethSendTrueTransaction = web3jt.ethSendTrueRawTransaction(hexValue).send();

            String txHashLocal = Hash.sha3(hexValue);
            String txHashRemote = ethSendTrueTransaction.getTransactionHash();

            System.out.println(" txHashLocal--->" + txHashLocal);
            System.out.println("txHashRemote--->" + txHashRemote);
//            if (ethSendTrueTransaction != null && !ethSendTrueTransaction.hasError()) {
//                String txHashLocal = Hash.sha3(hexValue);
//                String txHashRemote = ethSendTrueTransaction.getTransactionHash();
//
//                System.out.println(" txHashLocal--->" + txHashLocal);
//                System.out.println("txHashRemote--->" + txHashRemote);
//            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //普通转账使用和测试示例
    public static void main1(String[] args) {
        // http://39.98.43.179:8888
        // https://rpc.truescan.net/testnet
        // Web3j web3j = Web3j.build(new
        // HttpService("https://rpc.truescan.net/testnet"));
        Web3j web3j = Web3j.build(new HttpService("http://127.0.0.1:8888"));
//        String toAddress = "0x04d2252a3e0ca7c2aa81247ca33060855a34a808";
        String toAddress = "0x4cf807958b9f6d9fd9331397d7a89a079ef43288";


        Credentials credentials = Credentials.create("0x647EEEB80193A47A02D31939AF29EFA006DBE6DB45C8806AF764C18B262BB90B");
        int chainId = 18928;

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


    public static byte[] toByteArray(String hexString) {
        hexString = hexString.toLowerCase();
        final byte[] byteArray = new byte[hexString.length() / 2];
        int k = 0;
        for (int i = 0; i < byteArray.length; i++) {// 因为是16进制，最多只会占用4位，转换成字节需要两个16进制的字符，高位在先
            byte high = (byte) (Character.digit(hexString.charAt(k), 16) & 0xff);
            byte low = (byte) (Character.digit(hexString.charAt(k + 1), 16) & 0xff);
            byteArray[i] = (byte) (high << 4 | low);
            k += 2;
        }
        return byteArray;
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
