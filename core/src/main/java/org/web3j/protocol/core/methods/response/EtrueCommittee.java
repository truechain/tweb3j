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

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.web3j.protocol.core.Response;

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
public class EtrueCommittee extends Response<CommitteeInfo> {

    @Override
    @JsonDeserialize(using = CommitteeInfo.ResponseDeserialiser.class)
    public void setResult(CommitteeInfo result) {
        super.setResult(result);
    }

    public CommitteeInfo getCommittee() {
        return getResult();
    }


    /*public static class ResponseDeserialiser extends JsonDeserializer<CommitteeMember> {

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
    }*/
}
