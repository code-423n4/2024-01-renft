## Contracts that lock ether

```
Contract locking ether found:
    Contract Create2Deployer (src/Create2Deployer.sol#14-121) has payable functions:
        - Create2Deployer.deploy(bytes32,bytes) (src/Create2Deployer.sol#32-73)
    But does not have a function to withdraw the ether
```

**Justification**: When deploying a contract, the Create2 Deployer will forward all the ETH it receives in the call to the newly deployed contract. So, it does not need a function to withdraw ether.


## Re-entrancy Events

```
Reentrancy in PaymentEscrow._settlePayment(Item[],OrderType,address,address,uint256,uint256) (src/modules/PaymentEscrow.sol#215-283):
    External calls:
    - _settlePaymentProRata(item.token,paymentAmount,lender,renter,elapsedTime,totalTime) (src/modules/PaymentEscrow.sol#257-264)
            - (success,data) = token.call(abi.encodeWithSelector(IERC20.transfer.selector,to,value)) (src/modules/PaymentEscrow.sol#102-104)
    - _settlePaymentInFull(item.token,paymentAmount,item.settleTo,lender,renter) (src/modules/PaymentEscrow.sol#271-277)
            - (success,data) = token.call(abi.encodeWithSelector(IERC20.transfer.selector,to,value)) (src/modules/PaymentEscrow.sol#102-104)
    State variables written after the call(s):
    - _decreaseDeposit(item.token,item.amount) (src/modules/PaymentEscrow.sol#252)
            - balanceOf[token] -= amount (src/modules/PaymentEscrow.sol#294)
    PaymentEscrowBase.balanceOf (src/modules/PaymentEscrow.sol#25) can be used in cross function reentrancies:
    - PaymentEscrow._decreaseDeposit(address,uint256) (src/modules/PaymentEscrow.sol#292-295)
    - PaymentEscrow._increaseDeposit(address,uint256) (src/modules/PaymentEscrow.sol#304-307)
    - PaymentEscrowBase.balanceOf (src/modules/PaymentEscrow.sol#25)
    - PaymentEscrow.skim(address,address) (src/modules/PaymentEscrow.sol#397-412)
```

**Justification**: When stopping a rental, the hash of the rental order is checked against the storage module and is then deleted from storage after processing has finished. Because the protocol will revert when attempting to stop a rental that does not exist in storage, there is no way to successfully re-enter the protocol using the `settlePayment()` function.

## Uninitialized Local Variables

```
Create._processPayOrderOffer(Item[],SpentItem[],uint256).settleTo (src/policies/Create.sol#258) is a local variable never initialized
Create._processBaseOrderOffer(Item[],SpentItem[],uint256).itemType (src/policies/Create.sol#206) is a local variable never initialized
Create._processPayOrderOffer(Item[],SpentItem[],uint256).itemType (src/policies/Create.sol#257) is a local variable never initialized
Create._processPayOrderOffer(Item[],SpentItem[],uint256).totalPayments (src/policies/Create.sol#254) is a local variable never initialized
Create._processPayeeOrderConsideration(ReceivedItem[]).totalPayments (src/policies/Create.sol#372) is a local variable never initialized
Create._processPayeeOrderConsideration(ReceivedItem[]).totalRentals (src/policies/Create.sol#371) is a local variable never initialized
Create._processPayOrderOffer(Item[],SpentItem[],uint256).totalRentals (src/policies/Create.sol#253) is a local variable never initialized
```

**Justification**: Local variables are initialized, but via an if/else statement. Regardless of the path taken, the variables will be initialized.

## Unused Return

```
Kernel._reconfigurePolicies(Keycode) (src/Kernel.sol#540-550) ignores return value by dependents[i].configureDependencies() (src/Kernel.sol#548)
```

**Justification**: The return value is simply not needed in this particular statement.
