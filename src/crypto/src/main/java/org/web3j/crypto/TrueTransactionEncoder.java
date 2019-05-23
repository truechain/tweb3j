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
        //encode(rawTransaction, eip155SignatureData);
        
        int v = eip155SignatureData.getV();
        byte[] r = eip155SignatureData.getR();
        byte[] s = eip155SignatureData.getS();
        
        //二次签名
        byte[] encodedTransactionP = encodeP(trueRawTransaction,v ,r,s);
        Sign.SignatureDataP signatureDataP = Sign.signMessageP(encodedTransactionP, credentials.getEcKeyPair());
        
        Sign.SignatureDataP eip155SignatureDataP = createEip155SignatureDataP(signatureDataP, chainId);
        return encodeP(trueRawTransaction, eip155SignatureDataP,chainId);
    }

    public static Sign.SignatureData createEip155SignatureData(
            Sign.SignatureData signatureData, int chainId) {
        int v = signatureData.getV() + (chainId << 1) + 8;

        return new Sign.SignatureData(
                v, signatureData.getR(), signatureData.getS());
    }
    
    public static Sign.SignatureDataP createEip155SignatureDataP(
            Sign.SignatureDataP signatureDataP, int chainId) {
        int v = signatureDataP.getV() + (chainId << 1) + 8;
    
        return new Sign.SignatureDataP(
                v, signatureDataP.getR(), signatureDataP.getS());
    }

    public static byte[] encode(TrueRawTransaction trueRawTransaction) {
        return encode(trueRawTransaction, null);
    }

    public static byte[] encode(TrueRawTransaction trueRawTransaction, int chainId) {
        Sign.SignatureData signatureData = new Sign.SignatureData(
                chainId, new byte[] {}, new byte[] {});
        return encode(trueRawTransaction, signatureData);
    }
    
    public static byte[] encodeP(TrueRawTransaction trueRawTransaction, int v,byte[] r,byte[] s) {
        Sign.SignatureDataP signatureDataP = new Sign.SignatureDataP(v, r, s);
        return encodeP(trueRawTransaction, signatureDataP,v);
    }

    private static byte[] encode(TrueRawTransaction trueRawTransaction, Sign.SignatureData signatureData) {
        List<RlpType> values = asRlpValues(trueRawTransaction, signatureData);
        RlpList rlpList = new RlpList(values);
        return RlpEncoder.encode(rlpList);
    }
    
    private static byte[] encodeP(TrueRawTransaction trueRawTransaction, Sign.SignatureDataP signatureDataP,int chainId) {
        List<RlpType> values = asRlpValuesP(trueRawTransaction, signatureDataP,chainId);
        RlpList rlpList = new RlpList(values);
        return RlpEncoder.encode(rlpList);
    }

    static List<RlpType> asRlpValues(
        TrueRawTransaction trueRawTransaction, Sign.SignatureData signatureData) {
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

        if (signatureData != null) {
            result.add(RlpString.create(signatureData.getV()));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getR())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getS())));
        }

        result.add(RlpString.create(trueRawTransaction.getFee()));
        result.add(RlpString.create(trueRawTransaction.getPayment()));
        
        return result;
    }
    
    static List<RlpType> asRlpValuesP(
        TrueRawTransaction trueRawTransaction, Sign.SignatureDataP signatureDataP,int chainId) {
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

        if (signatureDataP != null) {
            result.add(RlpString.create(signatureDataP.getV()));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureDataP.getR())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureDataP.getS())));
        }

        result.add(RlpString.create(trueRawTransaction.getFee()));
        result.add(RlpString.create(trueRawTransaction.getPayment()));
        result.add(RlpString.create(chainId));
        
        return result;
    }
}
