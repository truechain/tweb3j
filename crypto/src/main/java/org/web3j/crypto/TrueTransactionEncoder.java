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
 * Create RLP encoded transaction, implementation as per p4 of the <a href="http://gavwood.com/paper.pdf">yellow
 * paper</a>.
 */
public class TrueTransactionEncoder {
    
    public static byte[] signMessage(TrueRawTransaction trueRawTransaction, Credentials credentials) {
        byte[] encodedTransaction = encode(trueRawTransaction);
        Sign.SignatureData signatureData = Sign.signMessage(
                encodedTransaction, credentials.getEcKeyPair());

        return encode(trueRawTransaction, signatureData);
    }

    public static byte[] signMessage(
        TrueRawTransaction trueRawTransaction, int chainId, Credentials credentials) {
        byte[] encodedTransaction = encode(trueRawTransaction, chainId);
        
        Sign.SignatureData signatureData = Sign.signMessage(
                encodedTransaction, credentials.getEcKeyPair());
        Sign.SignatureData eip155SignatureData = createEip155SignatureData(signatureData, chainId);
        
        //二次签名
        byte[] encodedTransactionP = encodeP(trueRawTransaction,eip155SignatureData,chainId);
        Sign.SignatureData signatureDataP = Sign.signMessage(encodedTransactionP, credentials.getEcKeyPair());
        
        Sign.SignatureData eip155SignatureDataP = createEip155SignatureData(signatureDataP, chainId);
        return encodeP(trueRawTransaction, eip155SignatureData,eip155SignatureDataP);
    }
    
    //代付签名
    public static byte[] signMessage_payment(TrueRawTransaction trueRawTransaction, int chainId,
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

    public static Sign.SignatureData createEip155SignatureData(Sign.SignatureData signatureData, int chainId) {
        int v = signatureData.getV() + (chainId << 1) + 8;

        return new Sign.SignatureData(v, signatureData.getR(), signatureData.getS());
    }

    public static byte[] encode(TrueRawTransaction trueRawTransaction) {
        return encode(trueRawTransaction, null);
    }

    public static byte[] encode(TrueRawTransaction trueRawTransaction, int chainId) {
        Sign.SignatureData signatureData = new Sign.SignatureData(chainId, new byte[] {}, new byte[] {});
        return encode(trueRawTransaction, signatureData);
    }

    public static byte[] encodeP(TrueRawTransaction trueRawTransaction, Sign.SignatureData signatureData, int chainId) {
        Sign.SignatureData signatureDataP = new Sign.SignatureData(chainId, new byte[] {}, new byte[] {});
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
            result.add(RlpString.create(signatureData.getV()));
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
            result.add(RlpString.create(signatureData.getV()));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getR())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getS())));
        }

        if (signatureDataP != null) {
            result.add(RlpString.create(signatureDataP.getV()));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureDataP.getR())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureDataP.getS())));
        }
        // result.add(RlpString.create(chainId));

        return result;
    }
}
