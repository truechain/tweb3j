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
package org.web3j.protocol.ipc;

/**
 * Windows named pipe implementation of our services API.
 *
 * <p>This implementation is experimental.
 */
public class WindowsIpcService extends IpcService {
    private final String ipcSocketPath;

    public WindowsIpcService(String ipcSocketPath) {
        super();
        this.ipcSocketPath = ipcSocketPath;
    }

    public WindowsIpcService(String ipcSocketPath, boolean includeRawResponse) {
        super(includeRawResponse);
        this.ipcSocketPath = ipcSocketPath;
    }

    @Override
    protected IOFacade getIO() {
        return new WindowsNamedPipe(ipcSocketPath);
    }
}
