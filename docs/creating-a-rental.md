## Creating a Rental

### Overview

Creating a rental order involves constructing and signing a valid seaport order with a special data payload so that our protocol's zone contract is invoked during the processing of the order.

### Creating the Seaport Order

When an EOA wants to list a rental order, they must first create and sign a seaport order. 


Seaport order components are structured as follows:
```
/**
 * @dev An order contains eleven components: an offerer, a zone (or account that
 *      can cancel the order or restrict who can fulfill the order depending on
 *      the type), the order type (specifying partial fill support as well as
 *      restricted order status), the start and end time, a hash that will be
 *      provided to the zone when validating restricted orders, a salt, a key
 *      corresponding to a given conduit, a counter, and an arbitrary number of
 *      offer items that can be spent along with consideration items that must
 *      be received by their respective recipient.
 */
struct OrderComponents {
    address offerer;
    address zone;
    OfferItem[] offer;
    ConsiderationItem[] consideration;
    OrderType orderType;
    uint256 startTime;
    uint256 endTime;
    bytes32 zoneHash;
    uint256 salt;
    bytes32 conduitKey;
    uint256 counter;
}
```

The items to pay particular attention to here are the `zone` and `zoneHash` fields.

For our protocol, the `zone` address will always be the address of the [Create Policy](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol).

Specifying a zone is crucial because a seaport order will not be routed through the protocol unless the `zone` field is given the right address.

The `zoneHash` is a hashed value of data which describes the unique values of this particular rental. After this order has been signed, a counterparty (the fulfiller) will pass the unhashed data which makes up the zone hash into the Seaport fulfillment function to prove to the protocol that both the lender and the renter of the order have agreed on the rental terms. 

### Constructing the Zone Hash

A zone hash is the EIP-712 hashed version of the following struct: 

```
/**
 * @dev Order metadata contains all the details supplied by the offerer when they sign an
 *      order. These items include the type of rental order, how long the rental will be
 *      active, any hooks associated with the order, and any data that should be emitted
 *      when the rental starts.
 */
struct OrderMetadata {
    // Type of order being created.
    OrderType orderType;
    // Duration of the rental in seconds.
    uint256 rentDuration;
    // Hooks that will act as middleware for the items in the order.
    Hook[] hooks;
    // Any extra data to be emitted upon order fulfillment.
    bytes emittedExtraData;
}
```

> To see how an OrderMetadata struct is converted into a EIP-712 typehash, please see the [Signer Package](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol).

`orderType`: When a lender wants to create a rental, they must choose an order type. There are 3 order types supported by the protocol, but only 2 are external and can be used by lenders. 
- `BASE`: This order type describes an order in which the lender will construct a seaport order that contains at least one ERC721 or ERC1155 offer item, and at least one ERC20 consideration item. A lender would select this order when they want to be paid by a renter in exchange for lending out their asset(s) for a specific amount of time.
- `PAY`: This order type describes an order in which the lender wishes to *pay* the renter for renting out their asset. This order must contain at least one ERC721 or ERC1155 offer item, and at least one ERC20 offer item. It must contain 0 consideration items. This may sound counter-intuitive but the rationale is that some lenders may get benefit (tokens, rewards, etc) from allowing others to interact with contracts (on-chain games, etc) with their assets to extract some type of value from the lended asset. 
- `PAYEE`: This order type cannot be specified by a lender and should result in a revert if specified. As such, it is not used during rental creation. `PAYEE` orders act as mirror images of a `PAY` order. In other words, a `PAYEE` order has 0 offer items, and should specify the offer items of the target `PAY` order as its own consideration items, with the proper recipient addresses.

`rentDuration`: This is the total duration of the rental in seconds.

`hooks`: These are the hooks which will be specified for the rental. Please see the documentation on [hooks](./hooks.md) for more info.

`emittedExtraData`: This is any extra data that the lender wishes to emit once a rental has been fulfilled.

After the `OrderMetadata` has been constructed, its hash can be constructed using a convenience function which exists on the [Create Policy](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol):

```
/**
 * @notice Derives the order metadata EIP-712 compliant hash from an `OrderMetadata`.
 *
 * @param metadata Order metadata converted to a hash.
*/
function getOrderMetadataHash(
    OrderMetadata memory metadata
) external view returns (bytes32) {
    return _deriveOrderMetadataHash(metadata);
}
```

The resulting value is what is used as the zone hash.

### Finalizing the Order

Once the order is properly constructed, it can be signed by the offerer and await fulfillment. For examples on order construction, you can view the solidity test cases specified [here](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/test/integration/Rent.t.sol).

