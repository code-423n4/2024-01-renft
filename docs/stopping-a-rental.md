## Stopping a Rental

### Overview

Stopping a rental order involves passing in the EIP-712 hash of a previously initiated rental order struct. There are two ways to stop orders: the first being by stopping a single order at a time, and the second being a way to batch stop multiple orders in a single contract call. 

### Conditions for Stopping

To stop the order, a `RentalOrder` struct must be created from emitted data during the rental creation process. 

Once obtained, a single order or multiple orders can be stopped using `stopRent()` or `stopRentBatch()`.

Certain cases must be met for a rental order to be considered valid for stopping:
- If the order is a `BASE` order, then it can only be stopped at or after the rental has expired. Any address can stop a `BASE` order once it has expired.
- If the order is a `PAY` order and the stopper is the lender of the order, then it does not matter whether the rental has expired. Any payments will be pro-rata split between the lender and renter. But if the stopper is not the lender, then the rental must have expired before it is allowed to be stopped.

For examples on order stopping, you can view the solidity test cases for [rental stopping](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/test/integration/StopRent.t.sol) and [batch rental stopping](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/test/integration/StopRentBatch.t.sol).




