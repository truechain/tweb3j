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
package org.web3j.utils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import io.reactivex.Flowable;
import io.reactivex.disposables.Disposable;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class FlowablesTests {

    @Test
    public void testRangeFlowable() throws InterruptedException {
        int count = 10;

        Flowable<BigInteger> flowable =
                Flowables.range(BigInteger.ZERO, BigInteger.valueOf(count - 1));

        List<BigInteger> expected = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            expected.add(BigInteger.valueOf(i));
        }

        runRangeTest(flowable, expected);
    }

    @Test
    public void testRangeDescendingFlowable() throws InterruptedException {
        int count = 10;

        Flowable<BigInteger> flowable =
                Flowables.range(BigInteger.ZERO, BigInteger.valueOf(count - 1), false);

        List<BigInteger> expected = new ArrayList<>(count);
        for (int i = count - 1; i >= 0; i--) {
            expected.add(BigInteger.valueOf(i));
        }

        runRangeTest(flowable, expected);
    }

    private void runRangeTest(Flowable<BigInteger> flowable, List<BigInteger> expected)
            throws InterruptedException {

        CountDownLatch transactionLatch = new CountDownLatch(expected.size());
        CountDownLatch completedLatch = new CountDownLatch(1);

        List<BigInteger> results = new ArrayList<>(expected.size());

        Disposable subscription =
                flowable.subscribe(
                        result -> {
                            results.add(result);
                            transactionLatch.countDown();
                        },
                        throwable -> fail(throwable.getMessage()),
                        () -> completedLatch.countDown());

        transactionLatch.await(1, TimeUnit.SECONDS);
        assertThat(results, equalTo(expected));

        subscription.dispose();

        completedLatch.await(1, TimeUnit.SECONDS);
        assertTrue(subscription.isDisposed());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRangeFlowableIllegalLowerBound() throws InterruptedException {
        Flowables.range(BigInteger.valueOf(-1), BigInteger.ONE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRangeFlowableIllegalBounds() throws InterruptedException {
        Flowables.range(BigInteger.TEN, BigInteger.ONE);
    }
}
