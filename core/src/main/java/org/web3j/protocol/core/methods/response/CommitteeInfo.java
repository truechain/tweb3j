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

import java.util.*;
import java.io.IOException;

/**
 * Block object returned by:
 *
 * <ul>
 *   <li>eth_getBlockByHash
 *   <li>eth_getBlockByNumber
 *   <li>eth_getUncleByBlockHashAndIndex
 *   <li>eth_getUncleByBlockNumberAndIndex
 * </ul>
 *
 * <p>See <a href="https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_gettransactionbyhash">docs</a>
 * for further details.
 *
 * <p>See the following <a href="https://github.com/ethcore/parity/issues/2401">issue</a> for
 * details on additional Parity fields present in EthBlock.
 */


public class CommitteeInfo {
    private String beginSnailNumber;
    private String endSnailNumber;
    private String memberCount;
    private String beginNumber;
    private String endNumber;

    private List<CommitteeMember> members;


    public CommitteeInfo() {
    }


    public CommitteeInfo(String beginSnailNumber, String endSnailNumber, String memberCount, String beginNumber, String endNumber) {
        this.beginSnailNumber = beginSnailNumber;
        this.endSnailNumber = endSnailNumber;
        this.memberCount = memberCount;
        this.beginNumber = beginNumber;
        this.endNumber = endNumber;
    }


    public static class CommitteeMember {
        public String coinbase;
        public String publickey;
        public String flag;
        public String mType;

        public String getCoinbase() {
            return coinbase;
        }

        public void setCoinbase(String coinbase) {
            this.coinbase = coinbase;
        }

        public String getPublickey() {
            return publickey;
        }

        public void setPublickey(String publickey) {
            this.publickey = publickey;
        }

        public String getFlag() {
            return flag;
        }

        public void setFlag(String flag) {
            this.flag = flag;
        }

        public String getmType() {
            return mType;
        }

        public void setmType(String mType) {
            this.mType = mType;
        }

        public static class ResponseDeserialiser extends JsonDeserializer<CommitteeMember> {

            private ObjectReader objectReader = ObjectMapperFactory.getObjectReader();

            @Override
            public CommitteeMember deserialize(
                    JsonParser jsonParser, DeserializationContext deserializationContext)
                    throws IOException {
                if (jsonParser.getCurrentToken() != JsonToken.VALUE_NULL) {
                    return objectReader.readValue(jsonParser, CommitteeMember.class);
                } else {
                    return null; // null is wrapped by Optional in above getter
                }
            }
        }
    }

    public List<CommitteeMember> getMembers() {
        return members;
    }

    public void setMembers(List<CommitteeMember> members) {
        this.members = members;
    }

    public String getBeginSnailNumber() {
        return beginSnailNumber;
    }

    public void setBeginSnailNumber(String beginSnailNumber) {
        this.beginSnailNumber = beginSnailNumber;
    }

    public String getEndSnailNumber() {
        return endSnailNumber;
    }

    public void setEndSnailNumber(String endSnailNumber) {
        this.endSnailNumber = endSnailNumber;
    }

    public String getMemberCount() {
        return memberCount;
    }

    public void setMemberCount(String memberCount) {
        this.memberCount = memberCount;
    }

    public String getBeginNumber() {
        return beginNumber;
    }

    public void setBeginNumber(String beginNumber) {
        this.beginNumber = beginNumber;
    }

    public String getEndNumber() {
        return endNumber;
    }

    public void setEndNumber(String endNumber) {
        this.endNumber = endNumber;
    }

    public static class ResponseDeserialiser extends JsonDeserializer<CommitteeInfo> {

        private ObjectReader objectReader = ObjectMapperFactory.getObjectReader();

        @Override
        public CommitteeInfo deserialize(
                JsonParser jsonParser, DeserializationContext deserializationContext)
                throws IOException {
            if (jsonParser.getCurrentToken() != JsonToken.VALUE_NULL) {
                return objectReader.readValue(jsonParser, CommitteeInfo.class);
            } else {
                return null; // null is wrapped by Optional in above getter
            }
        }
    }
}
