package org.web3j.crypto;

import org.web3j.crypto.Sign.SignatureData;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.rlp.RlpType;
import org.web3j.utils.Bytes;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Create RLP encoded transaction, implementation as per p4 of the <a href="http://gavwood.com/paper.pdf">yellow
 * paper</a>.
 */
public class TrueTransactionEncoder {

    private static final int CHAIN_ID_INC = 35;
    private static final int LOWER_REAL_V = 27;

    //发送者签名，chainId 为空
    public static byte[] signMessage(TrueRawTransaction trueRawTransaction, Credentials credentials) {
        byte[] encodedTransaction = encode(trueRawTransaction);
        Sign.SignatureData signatureData = Sign.signMessage(
                encodedTransaction, credentials.getEcKeyPair());

        return encode(trueRawTransaction, signatureData);
    }

    //发送者签名
    public static byte[] signMessage(
            TrueRawTransaction trueRawTransaction, long chainId, Credentials credentials) {
        byte[] encodedTransaction = encode(trueRawTransaction, chainId);

        Sign.SignatureData signatureData = Sign.signMessage(encodedTransaction, credentials.getEcKeyPair());
        Sign.SignatureData eip155SignatureData = createEip155SignatureData(signatureData, chainId);

        return encode(trueRawTransaction, eip155SignatureData);
    }

    //代付者签名
    public static byte[] signMessage_payment(TrueRawTransaction trueRawTransaction, SignatureData eip155SignatureData, long chainId,Credentials credentials_payment) {
        // 二次签名
        byte[] encodedTransactionP = encodeP(trueRawTransaction, eip155SignatureData, chainId);
        Sign.SignatureData signatureDataP = Sign.signMessage(encodedTransactionP, credentials_payment.getEcKeyPair());
        Sign.SignatureData eip155SignatureDataP = createEip155SignatureData(signatureDataP, chainId);

        return encodeP(trueRawTransaction, eip155SignatureData, eip155SignatureDataP);
    }

    //发送者和代付者签名
    public static byte[] signMessage_fromAndPayment(TrueRawTransaction trueRawTransaction, long chainId,
                                                    Credentials credentials, Credentials credentials_payment) {

        byte[] encodedTransaction = encode(trueRawTransaction, chainId);
        Sign.SignatureData signatureData = Sign.signMessage(encodedTransaction, credentials.getEcKeyPair());
        Sign.SignatureData eip155SignatureData = createEip155SignatureData(signatureData, chainId);

        // 二次签名
        byte[] encodedTransactionP = encodeP(trueRawTransaction, eip155SignatureData, chainId);
        Sign.SignatureData signatureDataP = Sign.signMessage(encodedTransactionP, credentials_payment.getEcKeyPair());
        Sign.SignatureData eip155SignatureDataP = createEip155SignatureData(signatureDataP, chainId);

        return encodeP(trueRawTransaction, eip155SignatureData, eip155SignatureDataP);
    }

//    public static Sign.SignatureData createEip155SignatureData(Sign.SignatureData signatureData, long chainId) {
//        BigInteger v = Numeric.toBigInt(signatureData.getV());
//        long c =(chainId << 1) + 8;
//        v = v.add(BigInteger.valueOf(c));
//        return new Sign.SignatureData(v.toByteArray(), signatureData.getR(), signatureData.getS());
//    }

    public static Sign.SignatureData createEip155SignatureData(
            Sign.SignatureData signatureData, long chainId) {
        BigInteger v = Numeric.toBigInt(signatureData.getV());
        v = v.subtract(BigInteger.valueOf(LOWER_REAL_V));
        v = v.add(BigInteger.valueOf(chainId * 2));
        v = v.add(BigInteger.valueOf(CHAIN_ID_INC));
        return new Sign.SignatureData(v.toByteArray(), signatureData.getR(), signatureData.getS());
    }

    public static byte[] encode(TrueRawTransaction trueRawTransaction) {
        return encode(trueRawTransaction, null);
    }

    public static byte[] encode(TrueRawTransaction trueRawTransaction, long chainId) {
//        BigInteger v = BigInteger.valueOf(chainId);
//        Sign.SignatureData signatureData = new Sign.SignatureData(v.toByteArray(), new byte[]{}, new byte[]{});
        Sign.SignatureData signatureData = new Sign.SignatureData(longToBytes(chainId), new byte[] {}, new byte[] {});
        return encode(trueRawTransaction, signatureData);
    }

    private static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }


//    public static byte[] encodeP(TrueRawTransaction trueRawTransaction, Sign.SignatureData signatureData, long chainId) {
//        BigInteger v = BigInteger.valueOf(chainId);
//
//        Sign.SignatureData signatureDataP = new Sign.SignatureData(v.toByteArray(), new byte[] {}, new byte[] {});
//        return encodeP(trueRawTransaction, signatureData, signatureDataP);
//    }

    public static byte[] encodeP(TrueRawTransaction trueRawTransaction, Sign.SignatureData signatureData, long chainId) {
        BigInteger v = BigInteger.valueOf(chainId);
        Sign.SignatureData signatureDataP = new Sign.SignatureData(v.toByteArray(), new byte[]{}, new byte[]{});
//        Sign.SignatureData signatureDataP = new Sign.SignatureData(longToBytes(chainId), new byte[] {}, new byte[] {});
        return encodeP(trueRawTransaction, signatureData, signatureDataP);
    }

    private static byte[] encode(TrueRawTransaction trueRawTransaction, Sign.SignatureData signatureData) {
        List<RlpType> values = asRlpValues(trueRawTransaction, signatureData);
        RlpList rlpList = new RlpList(values);
        return RlpEncoder.encode(rlpList);
    }

    private static byte[] encodeP(TrueRawTransaction trueRawTransaction, Sign.SignatureData signatureData,
                                  Sign.SignatureData signatureDataP) {
        List<RlpType> values = asRlpValuesP(trueRawTransaction, signatureData, signatureDataP);
        RlpList rlpList = new RlpList(values);
        return RlpEncoder.encode(rlpList);
    }

    static List<RlpType> asRlpValues(TrueRawTransaction trueRawTransaction, Sign.SignatureData signatureData) {
        List<RlpType> result = new ArrayList<>();

        result.add(RlpString.create(trueRawTransaction.getNonce()));
        result.add(RlpString.create(trueRawTransaction.getGasPrice()));
        result.add(RlpString.create(trueRawTransaction.getGasLimit()));

        // an empty to address (contract creation) should not be encoded as a numeric 0 value
        String to = trueRawTransaction.getTo();
        if (to != null && to.length() > 0) {
            // addresses that start with zeros should be encoded with the zeros included, not
            // as numeric values
            result.add(RlpString.create(Numeric.hexStringToByteArray(to)));
        } else {
            result.add(RlpString.create(""));
        }

        result.add(RlpString.create(trueRawTransaction.getValue()));

        // value field will already be hex encoded, so we need to convert into binary first
        byte[] data = Numeric.hexStringToByteArray(trueRawTransaction.getData());
        result.add(RlpString.create(data));

        result.add(RlpString.create(Numeric.hexStringToByteArray(trueRawTransaction.getPayment())));
        if (trueRawTransaction.getFee() == null) {
            result.add(RlpString.create(0));
        } else {
            result.add(RlpString.create(trueRawTransaction.getFee()));
        }

        if (signatureData != null) {
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getV())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getR())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getS())));
        }
        return result;
    }

    static List<RlpType> asRlpValuesP(TrueRawTransaction trueRawTransaction, Sign.SignatureData signatureData,
                                      Sign.SignatureData signatureDataP) {
        List<RlpType> result = new ArrayList<>();

        result.add(RlpString.create(trueRawTransaction.getNonce()));
        result.add(RlpString.create(trueRawTransaction.getGasPrice()));
        result.add(RlpString.create(trueRawTransaction.getGasLimit()));

        // an empty to address (contract creation) should not be encoded as a numeric 0 value
        String to = trueRawTransaction.getTo();
        if (to != null && to.length() > 0) {
            // addresses that start with zeros should be encoded with the zeros included, not
            // as numeric values
            result.add(RlpString.create(Numeric.hexStringToByteArray(to)));
        } else {
            result.add(RlpString.create(""));
        }

        result.add(RlpString.create(trueRawTransaction.getValue()));

        // value field will already be hex encoded, so we need to convert into binary first
        byte[] data = Numeric.hexStringToByteArray(trueRawTransaction.getData());
        result.add(RlpString.create(data));

        result.add(RlpString.create(Numeric.hexStringToByteArray(trueRawTransaction.getPayment())));
        // result.add(RlpString.create(trueRawTransaction.getPayment()));
        if (trueRawTransaction.getFee() == null) {
            result.add(RlpString.create(0));
        } else {
            result.add(RlpString.create(trueRawTransaction.getFee()));
        }

        if (signatureData != null) {
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getV())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getR())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getS())));
        }

        if (signatureDataP != null) {
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureDataP.getV())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureDataP.getR())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureDataP.getS())));
        }
        // result.add(RlpString.create(chainId));

        return result;
    }
}
