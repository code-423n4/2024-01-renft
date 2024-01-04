## Fulfilling a Rental

### Overview

Fulfilling a rental order involves interacting with one of Seaport's fulfillment functions to process a signed order. The fulfillment functions used can be found [here](https://github.com/re-nft/seaport-core/blob/3bccb8e1da43cbd9925e97cf59cb17c25d1eaf95/src/lib/Consideration.sol), and are listed below for convenience: 
- `fulfillAdvancedOrder`
- `fulfillAvailableAdvancedOrders`
- `matchAdvancedOrders`


### Calling a Fulfillment Function

Signed orders can be fulfilled by the protocol in a few ways depending on how many orders are being filled at once, and what type of orders are being fulfilled. 

`BASE` orders: A single `BASE` order can be fulfilled using `fulfillAdvancedOrder()`. Multiple `BASE` orders can be fulfilled using `fulfillAvailabeAdvancedOrders()`.

`PAY` orders: Both single and multiple `PAY` orders can be fulfilled using Seaport's `matchAdvancedOrders()`.

For examples of order fulfillment, you can look at the test engine code [here](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/test/fixtures/engine/OrderFulfiller.sol).

### Emitted Rental Order Data

After a rental order is created, only the hash of the `RentalOrder` struct is saved in storage. The rest of the data is emitted in the following event: 

```
/**
 * @dev Emitted when a new rental order is started. PAYEE orders are excluded from
 *      emitting this event.
 *
 * @param orderHash        Hash of the rental order struct.
 * @param emittedExtraData Data passed to the order to be emitted as an event.
 * @param seaportOrderHash Order hash of the seaport order struct.
 * @param items            Items in the rental order.
 * @param hooks            Hooks defined for the rental order.
 * @param orderType        Order type of the rental.
 * @param lender           Lender EOA of the assets in the order.
 * @param renter           Renter EOA of the assets in the order.
 * @param rentalWallet     Wallet contract which holds the rented assets.
 * @param startTimestamp   Timestamp which marks the start of the rental.
 * @param endTimestamp     Timestamp which marks the end of the rental.
*/
event RentalOrderStarted(
    bytes32 orderHash,
    bytes emittedExtraData,
    bytes32 seaportOrderHash,
    Item[] items,
    Hook[] hooks,
    OrderType orderType,
    address indexed lender,
    address indexed renter,
    address rentalWallet,
    uint256 startTimestamp,
    uint256 endTimestamp
);
```

This will be enough to manually re-create the rental order off-chain. A fully constructed `RentalOrder` struct will be needed to stop any rental order, and reclaim the assets. 