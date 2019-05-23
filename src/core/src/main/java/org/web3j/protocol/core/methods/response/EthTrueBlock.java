package org.web3j.protocol.core.methods.response;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import org.web3j.protocol.ObjectMapperFactory;
import org.web3j.protocol.core.Response;
import org.web3j.utils.Numeric;

/**
 * Block object returned by:
 * <ul>
 * <li>eth_getBlockByHash</li>
 * <li>eth_getBlockByNumber</li>
 * <li>eth_getUncleByBlockHashAndIndex</li>
 * <li>eth_getUncleByBlockNumberAndIndex</li>
 * </ul>
 *
 * <p>
 * See <a href="https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_gettransactionbyhash">docs</a> for further details.
 * </p>
 *
 * <p>
 * See the following <a href="https://github.com/ethcore/parity/issues/2401">issue</a> for details on additional Parity
 * fields present in EthBlock.
 * </p>
 */
public class EthTrueBlock extends Response<EthTrueBlock.TrueBlock> {

    @Override
    @JsonDeserialize(using = EthTrueBlock.ResponseDeserialiser.class)
    public void setResult(TrueBlock result) {
        super.setResult(result);
    }

    public TrueBlock getTrueBlock() {
        return getResult();
    }

    public static class TrueBlock {
        private String number;
        private String hash;
        private String parentHash;
        private String nonce;
        private String sha3Uncles;
        private String logsBloom;
        private String transactionsRoot;
        private String stateRoot;
        private String receiptsRoot;
        private String author;
        private String mixHash;
        private String extraData;
        private String size;
        private String gasLimit;
        private String gasUsed;
        private String timestamp;
        private List<TransactionResult> transactions;
        private List<String> sealFields;

        /**
         * �����ֶ�
         */
        // �����ÿ��ίԱ���Hash
        private String committeeHash;

        // �����ÿ��ίԱ��ǩ����Ϣ
        private List<String> signs;

        // �ڵ�ǰ���б�����������Hash����û�н�����ʱ��Ϊ Address(0)
        private String snailHash;

        // �ڵ�ǰ���б������������߶ȣ���û�н�����ʱ��Ϊ0
        private BigInteger snailNumber;

        public TrueBlock() {}

        public TrueBlock(String number, String hash, String parentHash, String nonce, String sha3Uncles,
            String logsBloom, String transactionsRoot, String stateRoot, String receiptsRoot, String author,
            String mixHash, String extraData, String size, String gasLimit, String gasUsed, String timestamp,
            List<TransactionResult> transactions, List<String> sealFields, String committeeHash, List<String> signs,
            String snailHash, BigInteger snailNumber) {
            this.number = number;
            this.hash = hash;
            this.parentHash = parentHash;
            this.nonce = nonce;
            this.sha3Uncles = sha3Uncles;
            this.logsBloom = logsBloom;
            this.transactionsRoot = transactionsRoot;
            this.stateRoot = stateRoot;
            this.receiptsRoot = receiptsRoot;
            this.author = author;
            this.mixHash = mixHash;
            this.extraData = extraData;
            this.size = size;
            this.gasLimit = gasLimit;
            this.gasUsed = gasUsed;
            this.timestamp = timestamp;
            this.transactions = transactions;
            this.sealFields = sealFields;
            this.committeeHash = committeeHash;
            this.signs = signs;
            this.snailHash = snailHash;
            this.snailNumber = snailNumber;
        }

        public BigInteger getNumber() {
            return Numeric.decodeQuantity(number);
        }

        public String getNumberRaw() {
            return number;
        }

        public void setNumber(String number) {
            this.number = number;
        }

        public String getHash() {
            return hash;
        }

        public void setHash(String hash) {
            this.hash = hash;
        }

        public String getParentHash() {
            return parentHash;
        }

        public void setParentHash(String parentHash) {
            this.parentHash = parentHash;
        }

        public BigInteger getNonce() {
            return Numeric.decodeQuantity(nonce);
        }

        public String getNonceRaw() {
            return nonce;
        }

        public void setNonce(String nonce) {
            this.nonce = nonce;
        }

        public String getSha3Uncles() {
            return sha3Uncles;
        }

        public void setSha3Uncles(String sha3Uncles) {
            this.sha3Uncles = sha3Uncles;
        }

        public String getLogsBloom() {
            return logsBloom;
        }

        public void setLogsBloom(String logsBloom) {
            this.logsBloom = logsBloom;
        }

        public String getTransactionsRoot() {
            return transactionsRoot;
        }

        public void setTransactionsRoot(String transactionsRoot) {
            this.transactionsRoot = transactionsRoot;
        }

        public String getStateRoot() {
            return stateRoot;
        }

        public void setStateRoot(String stateRoot) {
            this.stateRoot = stateRoot;
        }

        public String getReceiptsRoot() {
            return receiptsRoot;
        }

        public void setReceiptsRoot(String receiptsRoot) {
            this.receiptsRoot = receiptsRoot;
        }

        public String getAuthor() {
            return author;
        }

        public void setAuthor(String author) {
            this.author = author;
        }

        public String getMixHash() {
            return mixHash;
        }

        public void setMixHash(String mixHash) {
            this.mixHash = mixHash;
        }

        public String getExtraData() {
            return extraData;
        }

        public void setExtraData(String extraData) {
            this.extraData = extraData;
        }

        public BigInteger getSize() {
            return Numeric.decodeQuantity(size);
        }

        public String getSizeRaw() {
            return size;
        }

        public void setSize(String size) {
            this.size = size;
        }

        public BigInteger getGasLimit() {
            return Numeric.decodeQuantity(gasLimit);
        }

        public String getGasLimitRaw() {
            return gasLimit;
        }

        public void setGasLimit(String gasLimit) {
            this.gasLimit = gasLimit;
        }

        public BigInteger getGasUsed() {
            return Numeric.decodeQuantity(gasUsed);
        }

        public String getGasUsedRaw() {
            return gasUsed;
        }

        public void setGasUsed(String gasUsed) {
            this.gasUsed = gasUsed;
        }

        public BigInteger getTimestamp() {
            return Numeric.decodeQuantity(timestamp);
        }

        public String getTimestampRaw() {
            return timestamp;
        }

        public void setTimestamp(String timestamp) {
            this.timestamp = timestamp;
        }

        public List<TransactionResult> getTransactions() {
            return transactions;
        }

        @JsonDeserialize(using = ResultTransactionDeserialiser.class)
        public void setTransactions(List<TransactionResult> transactions) {
            this.transactions = transactions;
        }

        public List<String> getSealFields() {
            return sealFields;
        }

        public void setSealFields(List<String> sealFields) {
            this.sealFields = sealFields;
        }

        public String getCommitteeHash() {
            return committeeHash;
        }

        public void setCommitteeHash(String committeeHash) {
            this.committeeHash = committeeHash;
        }

        public List<String> getSigns() {
            return signs;
        }

        public void setSigns(List<String> signs) {
            this.signs = signs;
        }

        public String getSnailHash() {
            return snailHash;
        }

        public void setSnailHash(String snailHash) {
            this.snailHash = snailHash;
        }

        public BigInteger getSnailNumber() {
            return snailNumber;
        }

        public void setSnailNumber(BigInteger snailNumber) {
            this.snailNumber = snailNumber;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof TrueBlock)) {
                return false;
            }

            TrueBlock block = (TrueBlock)o;

            if (getNumberRaw() != null ? !getNumberRaw().equals(block.getNumberRaw()) : block.getNumberRaw() != null) {
                return false;
            }
            if (getHash() != null ? !getHash().equals(block.getHash()) : block.getHash() != null) {
                return false;
            }
            if (getParentHash() != null ? !getParentHash().equals(block.getParentHash())
                : block.getParentHash() != null) {
                return false;
            }
            if (getNonceRaw() != null ? !getNonceRaw().equals(block.getNonceRaw()) : block.getNonceRaw() != null) {
                return false;
            }
            if (getSha3Uncles() != null ? !getSha3Uncles().equals(block.getSha3Uncles())
                : block.getSha3Uncles() != null) {
                return false;
            }
            if (getLogsBloom() != null ? !getLogsBloom().equals(block.getLogsBloom()) : block.getLogsBloom() != null) {
                return false;
            }
            if (getTransactionsRoot() != null ? !getTransactionsRoot().equals(block.getTransactionsRoot())
                : block.getTransactionsRoot() != null) {
                return false;
            }
            if (getStateRoot() != null ? !getStateRoot().equals(block.getStateRoot()) : block.getStateRoot() != null) {
                return false;
            }
            if (getReceiptsRoot() != null ? !getReceiptsRoot().equals(block.getReceiptsRoot())
                : block.getReceiptsRoot() != null) {
                return false;
            }
            if (getAuthor() != null ? !getAuthor().equals(block.getAuthor()) : block.getAuthor() != null) {
                return false;
            }
            if (getMixHash() != null ? !getMixHash().equals(block.getMixHash()) : block.getMixHash() != null) {
                return false;
            }
            if (getExtraData() != null ? !getExtraData().equals(block.getExtraData()) : block.getExtraData() != null) {
                return false;
            }
            if (getSizeRaw() != null ? !getSizeRaw().equals(block.getSizeRaw()) : block.getSizeRaw() != null) {
                return false;
            }
            if (getGasLimitRaw() != null ? !getGasLimitRaw().equals(block.getGasLimitRaw())
                : block.getGasLimitRaw() != null) {
                return false;
            }
            if (getGasUsedRaw() != null ? !getGasUsedRaw().equals(block.getGasUsedRaw())
                : block.getGasUsedRaw() != null) {
                return false;
            }
            if (getTimestampRaw() != null ? !getTimestampRaw().equals(block.getTimestampRaw())
                : block.getTimestampRaw() != null) {
                return false;
            }
            if (getTransactions() != null ? !getTransactions().equals(block.getTransactions())
                : block.getTransactions() != null) {
                return false;
            }
            if (getCommitteeHash() != null ? !getCommitteeHash().equals(block.getCommitteeHash())
                : block.getCommitteeHash() != null) {
                return false;
            }
            if (getSigns() != null ? !getSigns().equals(block.getSigns()) : block.getSigns() != null) {
                return false;
            }
            if (getSnailHash() != null ? !getSnailHash().equals(block.getSnailHash()) : block.getSnailHash() != null) {
                return false;
            }
            if (getSnailNumber() != null ? !getSnailNumber().equals(block.getSnailNumber())
                : block.getSnailNumber() != null) {
                return false;
            }

            return getSealFields() != null ? getSealFields().equals(block.getSealFields())
                : block.getSealFields() == null;
        }

        @Override
        public int hashCode() {
            int result = getNumberRaw() != null ? getNumberRaw().hashCode() : 0;
            result = 31 * result + (getHash() != null ? getHash().hashCode() : 0);
            result = 31 * result + (getParentHash() != null ? getParentHash().hashCode() : 0);
            result = 31 * result + (getNonceRaw() != null ? getNonceRaw().hashCode() : 0);
            result = 31 * result + (getSha3Uncles() != null ? getSha3Uncles().hashCode() : 0);
            result = 31 * result + (getLogsBloom() != null ? getLogsBloom().hashCode() : 0);
            result = 31 * result + (getTransactionsRoot() != null ? getTransactionsRoot().hashCode() : 0);
            result = 31 * result + (getStateRoot() != null ? getStateRoot().hashCode() : 0);
            result = 31 * result + (getReceiptsRoot() != null ? getReceiptsRoot().hashCode() : 0);
            result = 31 * result + (getAuthor() != null ? getAuthor().hashCode() : 0);
            result = 31 * result + (getMixHash() != null ? getMixHash().hashCode() : 0);
            result = 31 * result + (getExtraData() != null ? getExtraData().hashCode() : 0);
            result = 31 * result + (getSizeRaw() != null ? getSizeRaw().hashCode() : 0);
            result = 31 * result + (getGasLimitRaw() != null ? getGasLimitRaw().hashCode() : 0);
            result = 31 * result + (getGasUsedRaw() != null ? getGasUsedRaw().hashCode() : 0);
            result = 31 * result + (getTimestampRaw() != null ? getTimestampRaw().hashCode() : 0);
            result = 31 * result + (getTransactions() != null ? getTransactions().hashCode() : 0);
            result = 31 * result + (getSealFields() != null ? getSealFields().hashCode() : 0);

            result = 31 * result + (getCommitteeHash() != null ? getCommitteeHash().hashCode() : 0);
            result = 31 * result + (getSigns() != null ? getSigns().hashCode() : 0);
            result = 31 * result + (getSnailHash() != null ? getSnailHash().hashCode() : 0);
            result = 31 * result + (getSnailNumber() != null ? getSnailNumber().hashCode() : 0);

            return result;
        }
    }

    public interface TransactionResult<T> {
        T get();
    }

    public static class TransactionHash implements TransactionResult<String> {
        private String value;

        public TransactionHash() {}

        public TransactionHash(String value) {
            this.value = value;
        }

        @Override
        public String get() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof TransactionHash)) {
                return false;
            }

            TransactionHash that = (TransactionHash)o;

            return value != null ? value.equals(that.value) : that.value == null;
        }

        @Override
        public int hashCode() {
            return value != null ? value.hashCode() : 0;
        }
    }

    public static class TransactionObject extends Transaction implements TransactionResult<Transaction> {
        public TransactionObject() {}

        public TransactionObject(String hash, String nonce, String blockHash, String blockNumber,
            String transactionIndex, String from, String to, String value, String gasPrice, String gas, String input,
            String creates, String publicKey, String raw, String r, String s, int v) {
            super(hash, nonce, blockHash, blockNumber, transactionIndex, from, to, value, gasPrice, gas, input, creates,
                publicKey, raw, r, s, v);
        }

        @Override
        public Transaction get() {
            return this;
        }
    }

    public static class ResultTransactionDeserialiser extends JsonDeserializer<List<TransactionResult>> {

        private ObjectReader objectReader = ObjectMapperFactory.getObjectReader();

        @Override
        public List<TransactionResult> deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
            throws IOException {

            List<TransactionResult> transactionResults = new ArrayList<>();
            JsonToken nextToken = jsonParser.nextToken();

            if (nextToken == JsonToken.START_OBJECT) {
                Iterator<TransactionObject> transactionObjectIterator =
                    objectReader.readValues(jsonParser, TransactionObject.class);
                while (transactionObjectIterator.hasNext()) {
                    transactionResults.add(transactionObjectIterator.next());
                }
            } else if (nextToken == JsonToken.VALUE_STRING) {
                jsonParser.getValueAsString();

                Iterator<TransactionHash> transactionHashIterator =
                    objectReader.readValues(jsonParser, TransactionHash.class);
                while (transactionHashIterator.hasNext()) {
                    transactionResults.add(transactionHashIterator.next());
                }
            }

            return transactionResults;
        }
    }

    public static class ResponseDeserialiser extends JsonDeserializer<TrueBlock> {

        private ObjectReader objectReader = ObjectMapperFactory.getObjectReader();

        @Override
        public TrueBlock deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
            throws IOException {
            if (jsonParser.getCurrentToken() != JsonToken.VALUE_NULL) {
                return objectReader.readValue(jsonParser, TrueBlock.class);
            } else {
                return null; // null is wrapped by Optional in above getter
            }
        }
    }
}
