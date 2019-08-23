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
package org.web3j.protocol.pantheon;

import java.util.Arrays;
import java.util.Optional;

import org.junit.Test;

import org.web3j.protocol.ResponseTester;
import org.web3j.protocol.admin.methods.response.BooleanResponse;
import org.web3j.protocol.core.methods.response.EthAccounts;
import org.web3j.protocol.pantheon.response.PantheonEthAccountsMapResponse;
import org.web3j.protocol.pantheon.response.privacy.PrivCreatePrivacyGroup;
import org.web3j.protocol.pantheon.response.privacy.PrivFindPrivacyGroup;
import org.web3j.protocol.pantheon.response.privacy.PrivGetPrivacyPrecompileAddress;
import org.web3j.protocol.pantheon.response.privacy.PrivGetPrivateTransaction;
import org.web3j.protocol.pantheon.response.privacy.PrivacyGroup;
import org.web3j.protocol.pantheon.response.privacy.PrivateTransactionLegacy;
import org.web3j.protocol.pantheon.response.privacy.PrivateTransactionWithPrivacyGroup;
import org.web3j.utils.Base64String;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class ResponseTest extends ResponseTester {

    @Test
    public void testClicqueGetSigners() {
        buildResponse(
                "{\n"
                        + "    \"jsonrpc\": \"2.0\",\n"
                        + "    \"id\": 1,\n"
                        + "    \"result\": [\"0x42eb768f2244c8811c63729a21a3569731535f06\","
                        + "\"0x7ffc57839b00206d1ad20c69a1981b489f772031\","
                        + "\"0xb279182d99e65703f0076e4812653aab85fca0f0\"]\n"
                        + "}");

        EthAccounts ethAccounts = deserialiseResponse(EthAccounts.class);
        assertThat(
                ethAccounts.getAccounts().toString(),
                is(
                        "[0x42eb768f2244c8811c63729a21a3569731535f06, "
                                + "0x7ffc57839b00206d1ad20c69a1981b489f772031, "
                                + "0xb279182d99e65703f0076e4812653aab85fca0f0]"));
    }

    @Test
    public void testClicqueProposals() {
        buildResponse(
                "{\n"
                        + "    \"jsonrpc\": \"2.0\",\n"
                        + "    \"id\": 1,\n"
                        + "    \"result\": {\"0x42eb768f2244c8811c63729a21a3569731535f07\": false,"
                        + "\"0x12eb759f2222d7711c63729a45c3585731521d01\": true}\n}");

        PantheonEthAccountsMapResponse mapResponse =
                deserialiseResponse(PantheonEthAccountsMapResponse.class);
        assertThat(
                mapResponse.getAccounts().toString(),
                is(
                        "{0x42eb768f2244c8811c63729a21a3569731535f07=false, "
                                + "0x12eb759f2222d7711c63729a45c3585731521d01=true}"));
    }

    @Test
    public void testEeaGetPrivateTransactionLegacy() {

        buildResponse(
                "{\n"
                        + "    \"id\":1,\n"
                        + "    \"jsonrpc\":\"2.0\",\n"
                        + "    \"result\": {\n"
                        + "        \"hash\":\"0xc6ef2fc5426d6ad6fd9e2a26abeab0aa2411b7ab17f30a99d3cb96aed1d1055b\",\n"
                        + "        \"nonce\":\"0x00\",\n"
                        + "        \"from\":\"0x407d73d8a49eeb85d32cf465507dd71d507100c1\",\n"
                        + "        \"to\":\"0x85h43d8a49eeb85d32cf465507dd71d507100c1\",\n"
                        + "        \"value\":\"0x7f110\",\n"
                        + "        \"gas\": \"0x7f110\",\n"
                        + "        \"gasPrice\":\"0x09184e72a000\",\n"
                        + "        \"input\":\"0x603880600c6000396000f300603880600c6000396000f3603880600c6000396000f360\",\n"
                        + "        \"r\":\"0xf115cc4d7516dd430046504e1c888198e0323e8ded016d755f89c226ba3481dc\",\n"
                        + "        \"s\":\"0x4a2ae8ee49f1100b5c0202b37ed8bacf4caeddebde6b7f77e12e7a55893e9f62\",\n"
                        + "        \"v\":\"0x00\",\n"
                        + "        \"privateFrom\":\"A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=\",\n"
                        + "        \"privateFor\":[\"A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=\",\"Ko2bVqD+nNlNYL5EE7y3IdOnviftjiizpjRt+HTuFBs=\"],\n"
                        + "        \"restriction\":\"restricted\""
                        + "  }\n"
                        + "}");
        PrivateTransactionLegacy privateTransaction =
                new PrivateTransactionLegacy(
                        "0xc6ef2fc5426d6ad6fd9e2a26abeab0aa2411b7ab17f30a99d3cb96aed1d1055b",
                        "0x00",
                        "0x407d73d8a49eeb85d32cf465507dd71d507100c1",
                        "0x85h43d8a49eeb85d32cf465507dd71d507100c1",
                        "0x7f110",
                        "0x7f110",
                        "0x09184e72a000",
                        "0x603880600c6000396000f300603880600c6000396000f3603880600c6000396000f360",
                        "0xf115cc4d7516dd430046504e1c888198e0323e8ded016d755f89c226ba3481dc",
                        "0x4a2ae8ee49f1100b5c0202b37ed8bacf4caeddebde6b7f77e12e7a55893e9f62",
                        "0x00",
                        Base64String.wrap("A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo="),
                        Base64String.wrapList(
                                "A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=",
                                "Ko2bVqD+nNlNYL5EE7y3IdOnviftjiizpjRt+HTuFBs="),
                        "restricted");

        PrivGetPrivateTransaction eeaPrivateTransaction =
                deserialiseResponse(PrivGetPrivateTransaction.class);
        assertThat(
                eeaPrivateTransaction.getPrivateTransaction().get(), equalTo(privateTransaction));
    }

    @Test
    public void testEeaGetPrivateTransactionPrivacyGroup() {
        buildResponse(
                "{\n"
                        + "    \"id\":1,\n"
                        + "    \"jsonrpc\":\"2.0\",\n"
                        + "    \"result\": {\n"
                        + "        \"hash\":\"0xc6ef2fc5426d6ad6fd9e2a26abeab0aa2411b7ab17f30a99d3cb96aed1d1055b\",\n"
                        + "        \"nonce\":\"0x00\",\n"
                        + "        \"from\":\"0x407d73d8a49eeb85d32cf465507dd71d507100c1\",\n"
                        + "        \"to\":\"0x85h43d8a49eeb85d32cf465507dd71d507100c1\",\n"
                        + "        \"value\":\"0x7f110\",\n"
                        + "        \"gas\": \"0x7f110\",\n"
                        + "        \"gasPrice\":\"0x09184e72a000\",\n"
                        + "        \"input\":\"0x603880600c6000396000f300603880600c6000396000f3603880600c6000396000f360\",\n"
                        + "        \"r\":\"0xf115cc4d7516dd430046504e1c888198e0323e8ded016d755f89c226ba3481dc\",\n"
                        + "        \"s\":\"0x4a2ae8ee49f1100b5c0202b37ed8bacf4caeddebde6b7f77e12e7a55893e9f62\",\n"
                        + "        \"v\":\"0x00\",\n"
                        + "        \"privateFrom\":\"A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=\",\n"
                        + "        \"privateFor\":\"A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=\",\n"
                        + "        \"restriction\":\"restricted\""
                        + "  }\n"
                        + "}");
        PrivateTransactionWithPrivacyGroup privateTransaction =
                new PrivateTransactionWithPrivacyGroup(
                        "0xc6ef2fc5426d6ad6fd9e2a26abeab0aa2411b7ab17f30a99d3cb96aed1d1055b",
                        "0x00",
                        "0x407d73d8a49eeb85d32cf465507dd71d507100c1",
                        "0x85h43d8a49eeb85d32cf465507dd71d507100c1",
                        "0x7f110",
                        "0x7f110",
                        "0x09184e72a000",
                        "0x603880600c6000396000f300603880600c6000396000f3603880600c6000396000f360",
                        "0xf115cc4d7516dd430046504e1c888198e0323e8ded016d755f89c226ba3481dc",
                        "0x4a2ae8ee49f1100b5c0202b37ed8bacf4caeddebde6b7f77e12e7a55893e9f62",
                        "0x00",
                        Base64String.wrap("A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo="),
                        Base64String.wrap("A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo="),
                        "restricted");

        PrivGetPrivateTransaction eeaPrivateTransaction =
                deserialiseResponse(PrivGetPrivateTransaction.class);
        assertThat(
                eeaPrivateTransaction.getPrivateTransaction().get(), equalTo(privateTransaction));
    }

    @Test
    public void testEeaGetPrivateTransactionNull() {
        buildResponse("{\n" + "  \"result\": null\n" + "}");

        PrivGetPrivateTransaction eeaPrivateTransaction =
                deserialiseResponse(PrivGetPrivateTransaction.class);
        assertThat(eeaPrivateTransaction.getPrivateTransaction(), is(Optional.empty()));
    }

    @Test
    public void testEeaGetPrivacyPrecompileAddress() {

        buildResponse(
                "{\n"
                        + "    \"jsonrpc\": \"2.0\",\n"
                        + "    \"id\": 1,\n"
                        + "    \"result\": \"0xb60e8dd61c5d32be8058bb8eb970870f07233155\"\n"
                        + "}");

        PrivGetPrivacyPrecompileAddress privGetPrivacyPrecompileAddress =
                deserialiseResponse(PrivGetPrivacyPrecompileAddress.class);
        assertThat(
                privGetPrivacyPrecompileAddress.getAddress(),
                is("0xb60e8dd61c5d32be8058bb8eb970870f07233155"));
    }

    @Test
    public void testEeaCreatePrivacyGroup() {

        buildResponse(
                "{\n"
                        + "    \"jsonrpc\": \"2.0\",\n"
                        + "    \"id\": 1,\n"
                        + "    \"result\": \"DyAOiF/ynpc+JXa2YAGB0bCitSlOMNm+ShmB/7M6C4w=\"\n"
                        + "}");

        PrivCreatePrivacyGroup privCreatePrivacyGroup =
                deserialiseResponse(PrivCreatePrivacyGroup.class);
        assertThat(
                privCreatePrivacyGroup.getPrivacyGroupId().toString(),
                is("DyAOiF/ynpc+JXa2YAGB0bCitSlOMNm+ShmB/7M6C4w="));
    }

    @Test
    public void testEeaDeletePrivacyGroup() {

        buildResponse(
                "{\n"
                        + "    \"jsonrpc\": \"2.0\",\n"
                        + "    \"id\": 1,\n"
                        + "    \"result\": \"true\"\n"
                        + "}");

        BooleanResponse eeaDeletePrivacyGroup = deserialiseResponse(BooleanResponse.class);
        assertThat(eeaDeletePrivacyGroup.success(), is(true));
    }

    @Test
    public void testEeaFindPrivacyGroup() {

        buildResponse(
                "{\n"
                        + "    \"jsonrpc\": \"2.0\",\n"
                        + "    \"id\": 1,\n"
                        + "    \"result\": [\n"
                        + "         {\n"
                        + "            \"privacyGroupId\":\"A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=\",\n"
                        + "            \"name\":\"PrivacyGroupName\",\n"
                        + "            \"description\":\"PrivacyGroupDescription\",\n"
                        + "            \"type\":\"LEGACY\",\n"
                        + "            \"members\": [\"A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=\"]\n"
                        + "         },\n"
                        + "         {\n"
                        + "            \"privacyGroupId\":\"A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=\",\n"
                        + "            \"name\":\"PrivacyGroupName\",\n"
                        + "            \"description\":\"PrivacyGroupDescription\",\n"
                        + "            \"type\":\"PANTHEON\",\n"
                        + "            \"members\": [\"A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=\"]\n"
                        + "         }\n"
                        + "    ]\n"
                        + "}");

        PrivacyGroup privacyGroup1 =
                new PrivacyGroup(
                        "A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=",
                        PrivacyGroup.Type.LEGACY,
                        "PrivacyGroupName",
                        "PrivacyGroupDescription",
                        Base64String.wrapList("A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo="));
        PrivacyGroup privacyGroup2 =
                new PrivacyGroup(
                        "A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=",
                        PrivacyGroup.Type.PANTHEON,
                        "PrivacyGroupName",
                        "PrivacyGroupDescription",
                        Base64String.wrapList("A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo="));

        PrivFindPrivacyGroup privFindPrivacyGroup = deserialiseResponse(PrivFindPrivacyGroup.class);
        assertThat(
                privFindPrivacyGroup.getGroups(), is(Arrays.asList(privacyGroup1, privacyGroup2)));
    }
}
