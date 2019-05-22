# tweb3j
基于web3j源码修改部分代码，主要是涉及chainId的修改，适用于通过Java服务调用TrueChain主网以及测试网相关功能。


# 示例

//发起转账
public static void main(String[] args) {
        Web3j web3j = Web3j.build(new HttpService("节点地址"));
        String toAddress = "收款地址";
        Credentials credentials = Credentials.create("账户私钥");
        int chainId = 节点chainId;

        try {
            TransactionReceipt transactionReceipt =
                Transfer.sendFunds(web3j, credentials, toAddress, 
                    new BigDecimal("1"), Convert.Unit.ETHER,chainId).send();
            
            String transactionHash = transactionReceipt.getTransactionHash();
            System.out.println("transactionHash------------------->" + transactionHash);
        } catch (TransactionException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
