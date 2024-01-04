## Rental Hooks

### Overview

When signing a rental order, the lender can decide to include an array of `Hook`
structs along with it. These are bespoke restrictions or added functionality
that can be applied to the rented token within the wallet. This protocol allows
for flexibility in how these hooks are implemented and what they restrict. A
common use-case for a hook is to prevent a call to a specific function selector
on a contract when renting a particular token ID from an ERC721/ERC1155
collection.

### Adding a Hook

Adding a hook contract to the protocol is an admin-permissioned action on the [Guard Policy](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Guard.sol) which is done via:

`updateHookStatus()` which enables a hook for use within the protocol.

`updateHookPath()` which specifies the contract which the rental wallet
interacts with that will activate the hook.

### Specifying hooks as a lender

When creating a rental, a `OrderMetadata` struct will be added to the order
which specifies extra parameters to pass along with the rentals:

```
struct OrderMetadata {
    // the type of order being created
    OrderType orderType;
    // the duration of the rental in seconds
    uint256 rentDuration;
    // the hooks that will act as middleware for the items in the order
    Hook[] hooks;
    // any extra data to be emitted upon order fulfillment
    bytes emittedExtraData;
}
```

Hooks can be added here to specify the unique functionality placed upon tokens
in the order. Only hooks which have been enabled by the admin will be valid when
passed to the `address target` field.

```
struct Hook {
    // the hook contract to target
    address target;
    // index of the item in the order to apply the hook to
    uint256 itemIndex;
    // any extra data that the hook will need. This will most likely
    // be some type of bitmap scheme
    bytes extraData;
}
```

### Routing a call to the proper hook

After a renter has successfully rented an ERC721/ERC1155, the [Guard Policy](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Guard.sol)
 will be invoked each time a transaction originates from the wallet. The
contract will check its mapping for any hooks in the path of the interacting
address.

If a hook exists, the control flow will be handed over to the hook contract for
further processing.

If no hook address was found, the rental guard contract contains basic
restrictions that prevents the usage of ERC721/ERC1155 state-changing functions.

### Implementing a hook

Example implementations of hooks can be found in the [src/examples/restricted-selector](https://github.com/re-nft/smart-contracts/tree/main/src/examples/restricted-selector) 
folder. 

Per each erc721 `GameToken` ID, this hook uses a bitmap which tracks any
function selectors that are restricted for that token ID only. Bitmaps allow
support for up to 256 function selectors on a single contract.

Using a `token ID -> bitmap` mapping allows the property that 2 or more tokens
from the same collection can be restricted in different ways based on how their
lenders defined the permissions.

### Extending a hook

Hooks are extendable. An allowlisted hook for a collection can be expanded even
further to allow for multiple child hooks that are routed to based on logic
defined in the parent hook. This pattern enables granular control flow of the
transaction execution for any requirements or restrictions that a rental may
have.