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
package org.web3j.codegen;

/** Command line utility classes. */
public class Console {
    public static void exitError(String message) {
        System.err.println(message);
        System.exit(1);
    }

    public static void exitError(Throwable throwable) {
        exitError(throwable.getMessage());
    }

    public static void exitSuccess(String message) {
        System.out.println(message);
        System.exit(0);
    }
}
