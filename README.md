# **前言：**

>tweb3j是基于web3j源码修改部分代码，主要是涉及chainId的修改，适用于通过Java服务调用TrueChain主网以及测试网相关功能。

<br/>

## 调用示例代码

```java
/*
* 发起转账
*/
public static void main(String[] args) {
        Web3j web3j = Web3j.build(new HttpService("节点地址"));
        String toAddress = "收款地址";
        Credentials credentials = Credentials.create("账户私钥");
        int chainId = 节点chainId;

        try {
            TransactionReceipt transactionReceipt =
                Transfer.sendFunds(web3j, credentials, toAddress, 
                    new BigDecimal("1"), Convert.Unit.ETHER,chainId).send();
            
            String transactionHash = transactionReceipt.getTransactionHash();
            System.out.println("transactionHash------------------->" + transactionHash);
        } catch (TransactionException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
```
<br/>

## <a name="home">涉及修改的Java文件</a>

* ### *core模块*
    * org.web3j.tx
        * <a href="#Transfer">Transfer.java</a>
        * <a href="#RawTransactionManager">RawTransactionManager.java</a>
 <br/>  
 
* ### *crypto模块*
   * org.web3j.crypto
        * <a href="#Sign">Sign.java</a>
        * <a href="#SignedRawTransaction">SignedRawTransaction.java</a>
        * <a href="#TransactionEncoder">TransactionEncoder.java</a>
 
 <br/>

### <a name="Transfer">Transfer.java </a>
```java
package org.web3j.tx;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.RemoteCall;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.exceptions.TransactionException;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

/**
 * Class for performing Ether transactions on the Ethereum blockchain.
 */
public class Transfer extends ManagedTransaction {

    // This is the cost to send Ether between parties
    public static final BigInteger GAS_LIMIT = BigInteger.valueOf(21000);

    public Transfer(Web3j web3j, TransactionManager transactionManager) {
        super(web3j, transactionManager);
    }

    /**
     * Given the duration required to execute a transaction, asyncronous execution is strongly
     * recommended via {@link Transfer#sendFunds(String, BigDecimal, Convert.Unit)}.
     *
     * @param toAddress destination address
     * @param value amount to send
     * @param unit of specified send
     *
     * @return {@link Optional} containing our transaction receipt
     * @throws ExecutionException if the computation threw an
     *                            exception
     * @throws InterruptedException if the current thread was interrupted
     *                              while waiting
     * @throws TransactionException if the transaction was not mined while waiting
     */
    private TransactionReceipt send(String toAddress, BigDecimal value, Convert.Unit unit)
            throws IOException, InterruptedException,
            TransactionException {

        BigInteger gasPrice = requestCurrentGasPrice();
        return send(toAddress, value, unit, gasPrice, GAS_LIMIT);
    }

    private TransactionReceipt send(
            String toAddress, BigDecimal value, Convert.Unit unit, BigInteger gasPrice,
            BigInteger gasLimit) throws IOException, InterruptedException,
            TransactionException {

        BigDecimal weiValue = Convert.toWei(value, unit);
        if (!Numeric.isIntegerValue(weiValue)) {
            throw new UnsupportedOperationException(
                    "Non decimal Wei value provided: " + value + " " + unit.toString()
                            + " = " + weiValue + " Wei");
        }

        String resolvedAddress = ensResolver.resolve(toAddress);
        return send(resolvedAddress, "", weiValue.toBigIntegerExact(), gasPrice, gasLimit);
    }

    //新增chainId参数
    public static RemoteCall<TransactionReceipt> sendFunds(
            Web3j web3j, Credentials credentials,
            String toAddress, BigDecimal value, Convert.Unit unit, int chainId) throws InterruptedException,
            IOException, TransactionException {

        TransactionManager transactionManager = new RawTransactionManager(web3j, credentials);

        return new RemoteCall<>(() ->
                new Transfer(web3j, transactionManager).send(toAddress, value, unit));
    }

    /**
     * Execute the provided function as a transaction asynchronously. This is intended for one-off
     * fund transfers. For multiple, create an instance.
     *
     * @param toAddress destination address
     * @param value amount to send
     * @param unit of specified send
     *
     * @return {@link RemoteCall} containing executing transaction
     */
    public RemoteCall<TransactionReceipt> sendFunds(
            String toAddress, BigDecimal value, Convert.Unit unit) {
        return new RemoteCall<>(() -> send(toAddress, value, unit));
    }

    public RemoteCall<TransactionReceipt> sendFunds(
            String toAddress, BigDecimal value, Convert.Unit unit, BigInteger gasPrice,
            BigInteger gasLimit) {
        return new RemoteCall<>(() -> send(toAddress, value, unit, gasPrice, gasLimit));
    }
}

```
<br/>

###  <a name="RawTransactionManager">RawTransactionManager.java</a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="#home">返回</a>
```java
package org.web3j.tx;

import java.io.IOException;
import java.math.BigInteger;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.tx.exceptions.TxHashMismatchException;
import org.web3j.tx.response.TransactionReceiptProcessor;
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
public class RawTransactionManager extends TransactionManager {

    private final Web3j web3j;
    final Credentials credentials;

    //兼容TrueChain主网修改chainId类型
    private final int chainId;

    protected TxHashVerifier txHashVerifier = new TxHashVerifier();

    public RawTransactionManager(Web3j web3j, Credentials credentials, int chainId) {
        super(web3j, credentials.getAddress());

        this.web3j = web3j;
        this.credentials = credentials;

        this.chainId = chainId;
    }

    //兼容TrueChain主网修改chainId类型
    public RawTransactionManager(
            Web3j web3j, Credentials credentials, int chainId,
            TransactionReceiptProcessor transactionReceiptProcessor) {
        super(transactionReceiptProcessor, credentials.getAddress());

        this.web3j = web3j;
        this.credentials = credentials;

        this.chainId = chainId;
    }

    //兼容TrueChain主网修改chainId类型
    public RawTransactionManager(
            Web3j web3j, Credentials credentials, int chainId, int attempts, long sleepDuration) {
        super(web3j, attempts, sleepDuration, credentials.getAddress());

        this.web3j = web3j;
        this.credentials = credentials;

        this.chainId = chainId;
    }

    public RawTransactionManager(Web3j web3j, Credentials credentials) {
        this(web3j, credentials, ChainId.NONE);
    }

    public RawTransactionManager(
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
    public EthSendTransaction sendTransaction(
            BigInteger gasPrice, BigInteger gasLimit, String to,
            String data, BigInteger value) throws IOException {

        BigInteger nonce = getNonce();

        RawTransaction rawTransaction = RawTransaction.createTransaction(
                nonce,
                gasPrice,
                gasLimit,
                to,
                value,
                data);

        return signAndSend(rawTransaction);
    }
    
    /*
     * @param rawTransaction a RawTransaction istance to be signed
     * @return The transaction signed and encoded without ever broadcasting it
     */
    public String sign(RawTransaction rawTransaction) {

        byte[] signedMessage;

        if (chainId > ChainId.NONE) {
            signedMessage = TransactionEncoder.signMessage(rawTransaction, chainId, credentials);
        } else {
            signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials);
        }

        return Numeric.toHexString(signedMessage);
    }

    public EthSendTransaction signAndSend(RawTransaction rawTransaction)
            throws IOException {
        String hexValue = sign(rawTransaction);
        EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send();

        //如果ethSendTransaction没有返回错误信息，则表示成功
        if (ethSendTransaction != null && !ethSendTransaction.hasError()) {
            return ethSendTransaction;
        }else{
            throw new IOException();
        }
    }
}

```
<br/>

###  <a name="Sign">Sign.java</a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="#home">返回</a>
```java
package org.web3j.crypto;

import java.math.BigInteger;
import java.security.SignatureException;
import java.util.Arrays;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

import org.web3j.utils.Numeric;

import static org.web3j.utils.Assertions.verifyPrecondition;

/**
 * <p>Transaction signing logic.</p>
 *
 * <p>Adapted from the
 * <a href="https://github.com/bitcoinj/bitcoinj/blob/master/core/src/main/java/org/bitcoinj/core/ECKey.java">
 * BitcoinJ ECKey</a> implementation.
 */
public class Sign {

    public static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    static final ECDomainParameters CURVE = new ECDomainParameters(
            CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
    static final BigInteger HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);

    static final String MESSAGE_PREFIX = "\u0019Ethereum Signed Message:\n";

    static byte[] getEthereumMessagePrefix(int messageLength) {
        return MESSAGE_PREFIX.concat(String.valueOf(messageLength)).getBytes();
    }

    static byte[] getEthereumMessageHash(byte[] message) {
        byte[] prefix = getEthereumMessagePrefix(message.length);

        byte[] result = new byte[prefix.length + message.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(message, 0, result, prefix.length, message.length);

        return Hash.sha3(result);
    }

    public static SignatureData signPrefixedMessage(byte[] message, ECKeyPair keyPair) {
        return signMessage(getEthereumMessageHash(message), keyPair, false);
    }

    public static SignatureData signMessage(byte[] message, ECKeyPair keyPair) {
        return signMessage(message, keyPair, true);
    }
    
    public static SignatureDataP signMessageP(byte[] message, ECKeyPair keyPair) {
        return signMessageP(message, keyPair, true);
    }

    public static SignatureData signMessage(byte[] message, ECKeyPair keyPair, boolean needToHash) {
        BigInteger publicKey = keyPair.getPublicKey();
        byte[] messageHash;
        if (needToHash) {
            messageHash = Hash.sha3(message);
        } else {
            messageHash = message;
        }

        ECDSASignature sig = keyPair.sign(messageHash);
        // Now we have to work backwards to figure out the recId needed to recover the signature.
        int recId = -1;
        for (int i = 0; i < 4; i++) {
            BigInteger k = recoverFromSignature(i, sig, messageHash);
            if (k != null && k.equals(publicKey)) {
                recId = i;
                break;
            }
        }
        if (recId == -1) {
            throw new RuntimeException(
                    "Could not construct a recoverable key. Are your credentials valid?");
        }

        int headerByte = recId + 27;

		//兼容TrueChain主网修改chainId类型
        // 1 header + 32 bytes for R + 32 bytes for S
        //byte v = (byte) headerByte;
        int v = headerByte;
        byte[] r = Numeric.toBytesPadded(sig.r, 32);
        byte[] s = Numeric.toBytesPadded(sig.s, 32);

        return new SignatureData(v, r, s);
    }
    
    public static SignatureDataP signMessageP(byte[] message, ECKeyPair keyPair, boolean needToHash) {
        BigInteger publicKey = keyPair.getPublicKey();
        byte[] messageHash;
        if (needToHash) {
            messageHash = Hash.sha3(message);
        } else {
            messageHash = message;
        }

        ECDSASignature sig = keyPair.sign(messageHash);
        // Now we have to work backwards to figure out the recId needed to recover the signature.
        int recId = -1;
        for (int i = 0; i < 4; i++) {
            BigInteger k = recoverFromSignature(i, sig, messageHash);
            if (k != null && k.equals(publicKey)) {
                recId = i;
                break;
            }
        }
        if (recId == -1) {
            throw new RuntimeException(
                    "Could not construct a recoverable key. Are your credentials valid?");
        }

        int headerByte = recId + 27;

        // 1 header + 32 bytes for R + 32 bytes for S
        byte v = (byte) headerByte;
        byte[] r = Numeric.toBytesPadded(sig.r, 32);
        byte[] s = Numeric.toBytesPadded(sig.s, 32);

        return new SignatureDataP(v, r, s);
    }

    /**
     * <p>Given the components of a signature and a selector value, recover and return the public
     * key that generated the signature according to the algorithm in SEC1v2 section 4.1.6.</p>
     *
     * <p>The recId is an index from 0 to 3 which indicates which of the 4 possible keys is the
     * correct one. Because the key recovery operation yields multiple potential keys, the correct
     * key must either be stored alongside the
     * signature, or you must be willing to try each recId in turn until you find one that outputs
     * the key you are expecting.</p>
     *
     * <p>If this method returns null it means recovery was not possible and recId should be
     * iterated.</p>
     *
     * <p>Given the above two points, a correct usage of this method is inside a for loop from
     * 0 to 3, and if the output is null OR a key that is not the one you expect, you try again
     * with the next recId.</p>
     *
     * @param recId Which possible key to recover.
     * @param sig the R and S components of the signature, wrapped.
     * @param message Hash of the data that was signed.
     * @return An ECKey containing only the public part, or null if recovery wasn't possible.
     */
    public static BigInteger recoverFromSignature(int recId, ECDSASignature sig, byte[] message) {
        verifyPrecondition(recId >= 0, "recId must be positive");
        verifyPrecondition(sig.r.signum() >= 0, "r must be positive");
        verifyPrecondition(sig.s.signum() >= 0, "s must be positive");
        verifyPrecondition(message != null, "message cannot be null");

        // 1.0 For j from 0 to h   (h == recId here and the loop is outside this function)
        //   1.1 Let x = r + jn
        BigInteger n = CURVE.getN();  // Curve order.
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = sig.r.add(i.multiply(n));
        //   1.2. Convert the integer x to an octet string X of length mlen using the conversion
        //        routine specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or mlen = ⌈m/8⌉.
        //   1.3. Convert the octet string (16 set binary digits)||X to an elliptic curve point R
        //        using the conversion routine specified in Section 2.3.4. If this conversion
        //        routine outputs "invalid", then do another iteration of Step 1.
        //
        // More concisely, what these points mean is to use X as a compressed public key.
        BigInteger prime = SecP256K1Curve.q;
        if (x.compareTo(prime) >= 0) {
            // Cannot have point co-ordinates larger than this as everything takes place modulo Q.
            return null;
        }
        // Compressed keys require you to know an extra bit of data about the y-coord as there are
        // two possibilities. So it's encoded in the recId.
        ECPoint R = decompressKey(x, (recId & 1) == 1);
        //   1.4. If nR != point at infinity, then do another iteration of Step 1 (callers
        //        responsibility).
        if (!R.multiply(n).isInfinity()) {
            return null;
        }
        //   1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.
        BigInteger e = new BigInteger(1, message);
        //   1.6. For k from 1 to 2 do the following.   (loop is outside this function via
        //        iterating recId)
        //   1.6.1. Compute a candidate public key as:
        //               Q = mi(r) * (sR - eG)
        //
        // Where mi(x) is the modular multiplicative inverse. We transform this into the following:
        //               Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
        // Where -e is the modular additive inverse of e, that is z such that z + e = 0 (mod n).
        // In the above equation ** is point multiplication and + is point addition (the EC group
        // operator).
        //
        // We can find the additive inverse by subtracting e from zero then taking the mod. For
        // example the additive inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and
        // -3 mod 11 = 8.
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = sig.r.modInverse(n);
        BigInteger srInv = rInv.multiply(sig.s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, R, srInv);

        byte[] qBytes = q.getEncoded(false);
        // We remove the prefix
        return new BigInteger(1, Arrays.copyOfRange(qBytes, 1, qBytes.length));
    }

    /** Decompress a compressed public key (x co-ord and low-bit of y-coord). */
    private static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.getCurve()));
        compEnc[0] = (byte)(yBit ? 0x03 : 0x02);
        return CURVE.getCurve().decodePoint(compEnc);
    }

    /**
     * Given an arbitrary piece of text and an Ethereum message signature encoded in bytes,
     * returns the public key that was used to sign it. This can then be compared to the expected
     * public key to determine if the signature was correct.
     *
     * @param message RLP encoded message.
     * @param signatureData The message signature components
     * @return the public key used to sign the message
     * @throws SignatureException If the public key could not be recovered or if there was a
     *     signature format error.
     */
    public static BigInteger signedMessageToKey(
            byte[] message, SignatureData signatureData) throws SignatureException {
        return signedMessageHashToKey(Hash.sha3(message), signatureData);
    }

    /**
     * Given an arbitrary message and an Ethereum message signature encoded in bytes,
     * returns the public key that was used to sign it. This can then be compared to the
     * expected public key to determine if the signature was correct.
     *
     * @param message The message.
     * @param signatureData The message signature components
     * @return the public key used to sign the message
     * @throws SignatureException If the public key could not be recovered or if there was a
     *     signature format error.
     */
    public static BigInteger signedPrefixedMessageToKey(
            byte[] message, SignatureData signatureData) throws SignatureException {
        return signedMessageHashToKey(getEthereumMessageHash(message), signatureData);
    }

    static BigInteger signedMessageHashToKey(
            byte[] messageHash, SignatureData signatureData) throws SignatureException {

        byte[] r = signatureData.getR();
        byte[] s = signatureData.getS();
        verifyPrecondition(r != null && r.length == 32, "r must be 32 bytes");
        verifyPrecondition(s != null && s.length == 32, "s must be 32 bytes");

        int header = signatureData.getV() & 0xFF;
        // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
        //                  0x1D = second key with even y, 0x1E = second key with odd y
        if (header < 27 || header > 34) {
            throw new SignatureException("Header byte out of range: " + header);
        }

        ECDSASignature sig = new ECDSASignature(
                new BigInteger(1, signatureData.getR()),
                new BigInteger(1, signatureData.getS()));

        int recId = header - 27;
        BigInteger key = recoverFromSignature(recId, sig, messageHash);
        if (key == null) {
            throw new SignatureException("Could not recover public key from signature");
        }
        return key;
    }

    /**
     * Returns public key from the given private key.
     *
     * @param privKey the private key to derive the public key from
     * @return BigInteger encoded public key
     */
    public static BigInteger publicKeyFromPrivate(BigInteger privKey) {
        ECPoint point = publicPointFromPrivate(privKey);

        byte[] encoded = point.getEncoded(false);
        return new BigInteger(1, Arrays.copyOfRange(encoded, 1, encoded.length));  // remove prefix
    }

    /**
     * Returns public key point from the given private key.
     *
     * @param privKey the private key to derive the public key from
     * @return ECPoint public key
     */
    public static ECPoint publicPointFromPrivate(BigInteger privKey) {
        /*
         * TODO: FixedPointCombMultiplier currently doesn't support scalars longer than the group
         * order, but that could change in future versions.
         */
        if (privKey.bitLength() > CURVE.getN().bitLength()) {
            privKey = privKey.mod(CURVE.getN());
        }
        return new FixedPointCombMultiplier().multiply(CURVE.getG(), privKey);
    }

    /**
     * Returns public key point from the given curve.
     *
     * @param bits representing the point on the curve
     * @return BigInteger encoded public key
     */
    public static BigInteger publicFromPoint(byte[] bits) {
        return new BigInteger(1, Arrays.copyOfRange(bits, 1, bits.length));  // remove prefix
    }

	//兼容TrueChain主网修改chainId类型
    public static class SignatureData {
        private final int v;
        private final byte[] r;
        private final byte[] s;

        public SignatureData(int v, byte[] r, byte[] s) {
            this.v = v;
            this.r = r;
            this.s = s;
        }

        public int getV() {
            return v;
        }

        public byte[] getR() {
            return r;
        }

        public byte[] getS() {
            return s;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }

            SignatureData that = (SignatureData) o;

            if (v != that.v) {
                return false;
            }
            if (!Arrays.equals(r, that.r)) {
                return false;
            }
            return Arrays.equals(s, that.s);
        }

        @Override
        public int hashCode() {
            int result = (int) v;
            result = 31 * result + Arrays.hashCode(r);
            result = 31 * result + Arrays.hashCode(s);
            return result;
        }
    }
    
    public static class SignatureDataP {
        private final int v;
        private final byte[] r;
        private final byte[] s;

        public SignatureDataP(int v, byte[] r, byte[] s) {
            this.v = v;
            this.r = r;
            this.s = s;
        }

        public int getV() {
            return v;
        }

        public byte[] getR() {
            return r;
        }

        public byte[] getS() {
            return s;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }

            SignatureDataP that = (SignatureDataP) o;

            if (v != that.v) {
                return false;
            }
            if (!Arrays.equals(r, that.r)) {
                return false;
            }
            return Arrays.equals(s, that.s);
        }

        @Override
        public int hashCode() {
            int result = (int) v;
            result = 31 * result + Arrays.hashCode(r);
            result = 31 * result + Arrays.hashCode(s);
            return result;
        }
    }
}

```

<br/>

###  <a name="SignedRawTransaction">SignedRawTransaction.java</a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="#home">返回</a>
```java
package org.web3j.crypto;

import java.math.BigInteger;
import java.security.SignatureException;

public class SignedRawTransaction extends RawTransaction {

    private static final int CHAIN_ID_INC = 35;
    private static final int LOWER_REAL_V = 27;

    private Sign.SignatureData signatureData;

    public SignedRawTransaction(BigInteger nonce, BigInteger gasPrice,
            BigInteger gasLimit, String to, BigInteger value, String data,
            Sign.SignatureData signatureData) {
        super(nonce, gasPrice, gasLimit, to, value, data);
        this.signatureData = signatureData;
    }

    public Sign.SignatureData getSignatureData() {
        return signatureData;
    }

    public String getFrom() throws SignatureException {
        Integer chainId = getChainId();
        byte[] encodedTransaction;
        if (null == chainId) {
            encodedTransaction = TransactionEncoder.encode(this);
        } else {
            encodedTransaction = TransactionEncoder.encode(this, chainId.byteValue());
        }

        //兼容TrueChain主网修改chainId类型
        int v = signatureData.getV();
        byte[] r = signatureData.getR();
        byte[] s = signatureData.getS();
        Sign.SignatureData signatureDataV = new Sign.SignatureData(getRealV(v), r, s);
        BigInteger key = Sign.signedMessageToKey(encodedTransaction, signatureDataV);
        return "0x" + Keys.getAddress(key);
    }

    public void verify(String from) throws SignatureException {
        String actualFrom = getFrom();
        if (!actualFrom.equals(from)) {
            throw new SignatureException("from mismatch");
        }
    }

    //兼容TrueChain主网修改chainId类型
    private int getRealV(int v) {
        if (v == LOWER_REAL_V || v == (LOWER_REAL_V + 1)) {
            return v;
        }
        byte realV = LOWER_REAL_V;
        int inc = 0;
        if ((int) v % 2 == 0) {
            inc = 1;
        }
        return (byte) (realV + inc);
    }

    //兼容TrueChain主网修改chainId类型
    public Integer getChainId() {
        int v = signatureData.getV();
        if (v == LOWER_REAL_V || v == (LOWER_REAL_V + 1)) {
            return null;
        }
        Integer chainId = (v - CHAIN_ID_INC) / 2;
        return chainId;
    }
}

```

<br/>

###  <a name="TransactionEncoder">TransactionEncoder.java</a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="#home">返回</a>

```java
package org.web3j.crypto;

import java.util.ArrayList;
import java.util.List;

import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.rlp.RlpType;
import org.web3j.utils.Bytes;
import org.web3j.utils.Numeric;

/**
 * Create RLP encoded transaction, implementation as per p4 of the
 * <a href="http://gavwood.com/paper.pdf">yellow paper</a>.
 */
public class TransactionEncoder {

    public static byte[] signMessage(RawTransaction rawTransaction, Credentials credentials) {
        byte[] encodedTransaction = encode(rawTransaction);
        Sign.SignatureData signatureData = Sign.signMessage(
                encodedTransaction, credentials.getEcKeyPair());

        return encode(rawTransaction, signatureData);
    }

	//兼容TrueChain主网修改chainId类型
    public static byte[] signMessage(
            RawTransaction rawTransaction, int chainId, Credentials credentials) {
        byte[] encodedTransaction = encode(rawTransaction, chainId);
        Sign.SignatureData signatureData = Sign.signMessage(
                encodedTransaction, credentials.getEcKeyPair());

        Sign.SignatureData eip155SignatureData = createEip155SignatureData(signatureData, chainId);
        return encode(rawTransaction, eip155SignatureData);
    }

	//兼容TrueChain主网修改chainId类型
    public static Sign.SignatureData createEip155SignatureData(
            Sign.SignatureData signatureData, int chainId) {
        try {
            int v = signatureData.getV() + (chainId << 1) + 8;
            
            return new Sign.SignatureData(
                v, signatureData.getR(), signatureData.getS());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    public static byte[] encode(RawTransaction rawTransaction) {
        return encode(rawTransaction, null);
    }

	//兼容TrueChain主网修改chainId类型
    public static byte[] encode(RawTransaction rawTransaction, int chainId) {
        Sign.SignatureData signatureData = new Sign.SignatureData(
                chainId, new byte[] {}, new byte[] {});
        return encode(rawTransaction, signatureData);
    }

    private static byte[] encode(RawTransaction rawTransaction, Sign.SignatureData signatureData) {
        List<RlpType> values = asRlpValues(rawTransaction, signatureData);
        RlpList rlpList = new RlpList(values);
        return RlpEncoder.encode(rlpList);
    }

    static List<RlpType> asRlpValues(
            RawTransaction rawTransaction, Sign.SignatureData signatureData) {
        List<RlpType> result = new ArrayList<>();

        result.add(RlpString.create(rawTransaction.getNonce()));
        result.add(RlpString.create(rawTransaction.getGasPrice()));
        result.add(RlpString.create(rawTransaction.getGasLimit()));

        // an empty to address (contract creation) should not be encoded as a numeric 0 value
        String to = rawTransaction.getTo();
        if (to != null && to.length() > 0) {
            // addresses that start with zeros should be encoded with the zeros included, not
            // as numeric values
            result.add(RlpString.create(Numeric.hexStringToByteArray(to)));
        } else {
            result.add(RlpString.create(""));
        }

        result.add(RlpString.create(rawTransaction.getValue()));

        // value field will already be hex encoded, so we need to convert into binary first
        byte[] data = Numeric.hexStringToByteArray(rawTransaction.getData());
        result.add(RlpString.create(data));

        if (signatureData != null) {
            result.add(RlpString.create(signatureData.getV()));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getR())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getS())));
        }

        return result;
    }
}

```
<br/>
