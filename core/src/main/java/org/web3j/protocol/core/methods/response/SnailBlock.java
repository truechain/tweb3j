/*
 * Copyright 2019 Web3 Labs LTD.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.web3j.protocol.core.methods.response;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectReader;
import org.web3j.protocol.ObjectMapperFactory;

import java.io.IOException;
import java.util.List;

public class SnailBlock {
    private String number;
    private String hash;
    private String parentHash;
    private String fruitsHash;
    private String nonce;
    private String mixHash;
    private String miner;
    private String difficulty;
    private String extraData;
    private String size;
    private String timestamp;
    private String beginFruitNumber;
    private String endFruitNumber;
    private List<Fruit> fruits;



    public SnailBlock() {
    }

    public SnailBlock(String number, String hash, String parentHash, String fruitsHash, String nonce, String mixHash, String miner, String difficulty, String extraData, String size, String timestamp, String beginFruitNumber, String endFruitNumber, List<Fruit> fruits) {
        this.number = number;
        this.hash = hash;
        this.parentHash = parentHash;
        this.fruitsHash = fruitsHash;
        this.nonce = nonce;
        this.mixHash = mixHash;
        this.miner = miner;
        this.difficulty = difficulty;
        this.extraData = extraData;
        this.size = size;
        this.timestamp = timestamp;
        this.beginFruitNumber = beginFruitNumber;
        this.endFruitNumber = endFruitNumber;
        this.fruits = fruits;
    }

    public List<Fruit> getFruits() {
        return fruits;
    }

    public void setFruits(List<Fruit> fruits) {
        this.fruits = fruits;
    }

    public String getNumber() {
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

    public String getFruitsHash() {
        return fruitsHash;
    }

    public void setFruitsHash(String fruitsHash) {
        this.fruitsHash = fruitsHash;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getMixHash() {
        return mixHash;
    }

    public void setMixHash(String mixHash) {
        this.mixHash = mixHash;
    }

    public String getMiner() {
        return miner;
    }

    public void setMiner(String miner) {
        this.miner = miner;
    }

    public String getDifficulty() {
        return difficulty;
    }

    public void setDifficulty(String difficulty) {
        this.difficulty = difficulty;
    }

    public String getExtraData() {
        return extraData;
    }

    public void setExtraData(String extraData) {
        this.extraData = extraData;
    }

    public String getSize() {
        return size;
    }

    public void setSize(String size) {
        this.size = size;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getBeginFruitNumber() {
        return beginFruitNumber;
    }

    public void setBeginFruitNumber(String beginFruitNumber) {
        this.beginFruitNumber = beginFruitNumber;
    }

    public String getEndFruitNumber() {
        return endFruitNumber;
    }

    public void setEndFruitNumber(String endFruitNumber) {
        this.endFruitNumber = endFruitNumber;
    }



    public static class ResponseDeserialiser extends JsonDeserializer<SnailBlock> {
        private ObjectReader objectReader = ObjectMapperFactory.getObjectReader();

        @Override
        public SnailBlock deserialize(
                JsonParser jsonParser, DeserializationContext deserializationContext)
                throws IOException {
            if (jsonParser.getCurrentToken() != JsonToken.VALUE_NULL) {
                return objectReader.readValue(jsonParser, SnailBlock.class);
            } else {
                return null; // null is wrapped by Optional in above getter
            }
        }
    }
}
