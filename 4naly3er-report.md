**Summary**

- [Report](#report)
  - [Gas Optimizations](#gas-optimizations)
    - [\[GAS-1\] Using bools for storage incurs overhead](#gas-1-using-bools-for-storage-incurs-overhead)
    - [\[GAS-2\] Cache array length outside of loop](#gas-2-cache-array-length-outside-of-loop)
    - [\[GAS-3\] For Operations that will not overflow, you could use unchecked](#gas-3-for-operations-that-will-not-overflow-you-could-use-unchecked)
    - [\[GAS-4\] Don't initialize variables with default value](#gas-4-dont-initialize-variables-with-default-value)
    - [\[GAS-5\] Functions guaranteed to revert when called by normal users can be marked `payable`](#gas-5-functions-guaranteed-to-revert-when-called-by-normal-users-can-be-marked-payable)
    - [\[GAS-6\] `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too)](#gas-6-i-costs-less-gas-than-i-especially-when-its-used-in-for-loops---ii---too)
    - [\[GAS-7\] Use != 0 instead of \> 0 for unsigned integer comparison](#gas-7-use--0-instead-of--0-for-unsigned-integer-comparison)
  - [Low Issues](#low-issues)
    - [\[L-1\]  `abi.encodePacked()` should not be used with dynamic types when passing the result to a hash function such as `keccak256()`](#l-1--abiencodepacked-should-not-be-used-with-dynamic-types-when-passing-the-result-to-a-hash-function-such-as-keccak256)
    - [\[L-2\] Empty Function Body - Consider commenting why](#l-2-empty-function-body---consider-commenting-why)
    - [\[L-3\] Initializers could be front-run](#l-3-initializers-could-be-front-run)
  - [Medium Issues](#medium-issues)
    - [\[M-1\] Centralization Risk for trusted owners](#m-1-centralization-risk-for-trusted-owners)
      - [Impact](#impact)

# Report

## Gas Optimizations

| |Issue|Instances|
|-|:-|:-:|
| [GAS-1](#GAS-1) | Using bools for storage incurs overhead | 8 |
| [GAS-2](#GAS-2) | Cache array length outside of loop | 21 |
| [GAS-3](#GAS-3) | For Operations that will not overflow, you could use unchecked | 274 |
| [GAS-4](#GAS-4) | Don't initialize variables with default value | 18 |
| [GAS-5](#GAS-5) | Functions guaranteed to revert when called by normal users can be marked `payable` | 21 |
| [GAS-6](#GAS-6) | `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too) | 5 |
| [GAS-7](#GAS-7) | Use != 0 instead of > 0 for unsigned integer comparison | 5 |

### <a name="GAS-1"></a>[GAS-1] Using bools for storage incurs overhead

Use uint256(1) and uint256(2) for true/false to avoid a Gwarmaccess (100 gas), and to avoid Gsset (20000 gas) when changing from ‘false’ to ‘true’, after having been ‘true’ in the past. See [source](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/58f635312aa21f947cae5f8578638a85aa2519f5/contracts/security/ReentrancyGuard.sol#L23-L27).

*Instances (8)*:

```solidity
File: src/Create2Deployer.sol

16:     mapping(address => bool) public deployed;

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol)

```solidity
File: src/Kernel.sol

116:     bool public isActive;

221:     mapping(Keycode => mapping(Policy => mapping(bytes4 => bool)))

229:     mapping(address => mapping(Role => bool)) public hasRole;

230:     mapping(Role => bool) public isRole;

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol)

```solidity
File: src/modules/Storage.sol

20:     mapping(bytes32 orderHash => bool isActive) public orders;

55:     mapping(address delegate => bool isWhitelisted) public whitelistedDelegates;

58:     mapping(address extension => bool isWhitelisted) public whitelistedExtensions;

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol)

### <a name="GAS-2"></a>[GAS-2] Cache array length outside of loop

If not cached, the solidity compiler will always read the length of the array during each iteration. That is, if it is a storage array, this is an extra sload operation (100 additional extra gas for each iteration except for the first) and if it is a memory array, this is an extra mload operation (3 additional gas for each iteration except for the first).

*Instances (21)*:

```solidity
File: src/modules/PaymentEscrow.sol

231:         for (uint256 i = 0; i < items.length; ++i) {

341:         for (uint256 i = 0; i < orders.length; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol)

```solidity
File: src/modules/Storage.sol

197:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {

229:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {

249:         for (uint256 i = 0; i < orderHashes.length; ++i) {

260:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol)

```solidity
File: src/packages/Signer.sol

170:         for (uint256 i = 0; i < order.items.length; ++i) {

176:         for (uint256 i = 0; i < order.hooks.length; ++i) {

225:         for (uint256 i = 0; i < metadata.hooks.length; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol)

```solidity
File: src/policies/Create.sol

209:         for (uint256 i; i < offers.length; ++i) {

261:         for (uint256 i; i < offers.length; ++i) {

337:         for (uint256 i; i < considerations.length; ++i) {

375:         for (uint256 i; i < considerations.length; ++i) {

475:         for (uint256 i = 0; i < hooks.length; ++i) {

567:             for (uint256 i; i < items.length; ++i) {

599:             for (uint256 i = 0; i < items.length; ++i) {

695:         for (uint256 i = 0; i < executions.length; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol)

```solidity
File: src/policies/Stop.sol

205:         for (uint256 i = 0; i < hooks.length; ++i) {

276:         for (uint256 i; i < order.items.length; ++i) {

324:         for (uint256 i = 0; i < orders.length; ++i) {

333:             for (uint256 j = 0; j < orders[i].items.length; ++j) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol)

### <a name="GAS-3"></a>[GAS-3] For Operations that will not overflow, you could use unchecked

*Instances (274)*:

```solidity
File: src/Create2Deployer.sol

4: import {Errors} from "@src/libraries/Errors.sol";

4: import {Errors} from "@src/libraries/Errors.sol";

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol)

```solidity
File: src/Kernel.sol

9: } from "@src/libraries/KernelUtils.sol";

9: } from "@src/libraries/KernelUtils.sol";

10: import {Actions, Keycode, Role, Permissions} from "@src/libraries/RentalStructs.sol";

10: import {Actions, Keycode, Role, Permissions} from "@src/libraries/RentalStructs.sol";

11: import {Errors} from "@src/libraries/Errors.sol";

11: import {Errors} from "@src/libraries/Errors.sol";

12: import {Events} from "src/libraries/Events.sol";

12: import {Events} from "src/libraries/Events.sol";

213:     mapping(Keycode => Module) public getModuleForKeycode; // get contract for module keycode.

213:     mapping(Keycode => Module) public getModuleForKeycode; // get contract for module keycode.

214:     mapping(Module => Keycode) public getKeycodeForModule; // get module keycode for contract.

214:     mapping(Module => Keycode) public getKeycodeForModule; // get module keycode for contract.

222:         public modulePermissions; // for policy addr, check if they have permission to call the function in the module.

222:         public modulePermissions; // for policy addr, check if they have permission to call the function in the module.

431:         getPolicyIndex[policy_] = activePolicies.length - 1;

438:         for (uint256 i; i < depLength; ++i) {

438:         for (uint256 i; i < depLength; ++i) {

445:             getDependentIndex[keycode][policy_] = moduleDependents[keycode].length - 1;

469:         Policy lastPolicy = activePolicies[activePolicies.length - 1];

512:         for (uint256 i; i < keycodeLen; ++i) {

512:         for (uint256 i; i < keycodeLen; ++i) {

521:         for (uint256 j; j < policiesLen; ++j) {

521:         for (uint256 j; j < policiesLen; ++j) {

546:         for (uint256 i; i < depLength; ++i) {

546:         for (uint256 i; i < depLength; ++i) {

566:         for (uint256 i = 0; i < reqLength; ++i) {

566:         for (uint256 i = 0; i < reqLength; ++i) {

592:         for (uint256 i; i < depcLength; ++i) {

592:         for (uint256 i; i < depcLength; ++i) {

601:             Policy lastPolicy = dependents[dependents.length - 1];

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol)

```solidity
File: src/modules/PaymentEscrow.sol

4: import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";

4: import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";

4: import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";

4: import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";

6: import {Kernel, Module, Keycode} from "@src/Kernel.sol";

7: import {Proxiable} from "@src/proxy/Proxiable.sol";

7: import {Proxiable} from "@src/proxy/Proxiable.sol";

14: } from "@src/libraries/RentalStructs.sol";

14: } from "@src/libraries/RentalStructs.sol";

15: import {Errors} from "@src/libraries/Errors.sol";

15: import {Errors} from "@src/libraries/Errors.sol";

16: import {Events} from "@src/libraries/Events.sol";

16: import {Events} from "@src/libraries/Events.sol";

17: import {RentalUtils} from "@src/libraries/RentalUtils.sol";

17: import {RentalUtils} from "@src/libraries/RentalUtils.sol";

90:         return (amount * fee) / 10000;

90:         return (amount * fee) / 10000;

138:         uint256 numerator = (amount * elapsedTime) * 1000;

138:         uint256 numerator = (amount * elapsedTime) * 1000;

142:         renterAmount = ((numerator / totalTime) + 500) / 1000;

142:         renterAmount = ((numerator / totalTime) + 500) / 1000;

142:         renterAmount = ((numerator / totalTime) + 500) / 1000;

145:         lenderAmount = amount - renterAmount;

224:         uint256 elapsedTime = block.timestamp - start;

225:         uint256 totalTime = end - start;

231:         for (uint256 i = 0; i < items.length; ++i) {

231:         for (uint256 i = 0; i < items.length; ++i) {

247:                     paymentAmount -= paymentFee;

294:         balanceOf[token] -= amount;

306:         balanceOf[token] += amount;

341:         for (uint256 i = 0; i < orders.length; ++i) {

341:         for (uint256 i = 0; i < orders.length; ++i) {

405:         uint256 skimmedBalance = trueBalance - syncedBalance;

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol)

```solidity
File: src/modules/Storage.sol

4: import {Kernel, Module, Keycode} from "@src/Kernel.sol";

5: import {Proxiable} from "@src/proxy/Proxiable.sol";

5: import {Proxiable} from "@src/proxy/Proxiable.sol";

6: import {RentalUtils} from "@src/libraries/RentalUtils.sol";

6: import {RentalUtils} from "@src/libraries/RentalUtils.sol";

7: import {RentalId, RentalAssetUpdate} from "@src/libraries/RentalStructs.sol";

7: import {RentalId, RentalAssetUpdate} from "@src/libraries/RentalStructs.sol";

8: import {Errors} from "@src/libraries/Errors.sol";

8: import {Errors} from "@src/libraries/Errors.sol";

197:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {

197:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {

201:             rentedAssets[asset.rentalId] += asset.amount;

229:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {

229:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {

233:             rentedAssets[asset.rentalId] -= asset.amount;

249:         for (uint256 i = 0; i < orderHashes.length; ++i) {

249:         for (uint256 i = 0; i < orderHashes.length; ++i) {

260:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {

260:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {

264:             rentedAssets[asset.rentalId] -= asset.amount;

276:         uint256 newSafeCount = totalSafes + 1;

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol)

```solidity
File: src/packages/Accumulator.sol

4: import {RentalId, RentalAssetUpdate} from "@src/libraries/RentalStructs.sol";

4: import {RentalId, RentalAssetUpdate} from "@src/libraries/RentalStructs.sol";

120:         for (uint256 i = 0; i < rentalAssetUpdateLength; ++i) {

120:         for (uint256 i = 0; i < rentalAssetUpdateLength; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol)

```solidity
File: src/packages/Reclaimer.sol

4: import {IERC721} from "@openzeppelin-contracts/token/ERC721/IERC721.sol";

4: import {IERC721} from "@openzeppelin-contracts/token/ERC721/IERC721.sol";

4: import {IERC721} from "@openzeppelin-contracts/token/ERC721/IERC721.sol";

4: import {IERC721} from "@openzeppelin-contracts/token/ERC721/IERC721.sol";

5: import {IERC1155} from "@openzeppelin-contracts/token/ERC1155/IERC1155.sol";

5: import {IERC1155} from "@openzeppelin-contracts/token/ERC1155/IERC1155.sol";

5: import {IERC1155} from "@openzeppelin-contracts/token/ERC1155/IERC1155.sol";

5: import {IERC1155} from "@openzeppelin-contracts/token/ERC1155/IERC1155.sol";

7: import {RentalOrder, Item, ItemType} from "@src/libraries/RentalStructs.sol";

7: import {RentalOrder, Item, ItemType} from "@src/libraries/RentalStructs.sol";

8: import {Errors} from "@src/libraries/Errors.sol";

8: import {Errors} from "@src/libraries/Errors.sol";

90:         for (uint256 i = 0; i < itemCount; ++i) {

90:         for (uint256 i = 0; i < itemCount; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol)

```solidity
File: src/packages/Signer.sol

4: import {ECDSA} from "@openzeppelin-contracts/utils/cryptography/ECDSA.sol";

4: import {ECDSA} from "@openzeppelin-contracts/utils/cryptography/ECDSA.sol";

4: import {ECDSA} from "@openzeppelin-contracts/utils/cryptography/ECDSA.sol";

4: import {ECDSA} from "@openzeppelin-contracts/utils/cryptography/ECDSA.sol";

13: } from "@src/libraries/RentalStructs.sol";

13: } from "@src/libraries/RentalStructs.sol";

14: import {Errors} from "@src/libraries/Errors.sol";

14: import {Errors} from "@src/libraries/Errors.sol";

25:     string internal constant _NAME = "ReNFT-Rentals";

170:         for (uint256 i = 0; i < order.items.length; ++i) {

170:         for (uint256 i = 0; i < order.items.length; ++i) {

176:         for (uint256 i = 0; i < order.hooks.length; ++i) {

176:         for (uint256 i = 0; i < order.hooks.length; ++i) {

225:         for (uint256 i = 0; i < metadata.hooks.length; ++i) {

225:         for (uint256 i = 0; i < metadata.hooks.length; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol)

```solidity
File: src/policies/Admin.sol

4: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol";

5: import {toKeycode} from "@src/libraries/KernelUtils.sol";

5: import {toKeycode} from "@src/libraries/KernelUtils.sol";

6: import {Storage} from "@src/modules/Storage.sol";

6: import {Storage} from "@src/modules/Storage.sol";

7: import {PaymentEscrow} from "@src/modules/PaymentEscrow.sol";

7: import {PaymentEscrow} from "@src/modules/PaymentEscrow.sol";

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol)

```solidity
File: src/policies/Create.sol

4: import {ZoneParameters} from "@seaport-core/lib/rental/ConsiderationStructs.sol";

4: import {ZoneParameters} from "@seaport-core/lib/rental/ConsiderationStructs.sol";

4: import {ZoneParameters} from "@seaport-core/lib/rental/ConsiderationStructs.sol";

4: import {ZoneParameters} from "@seaport-core/lib/rental/ConsiderationStructs.sol";

5: import {ReceivedItem, SpentItem} from "@seaport-types/lib/ConsiderationStructs.sol";

5: import {ReceivedItem, SpentItem} from "@seaport-types/lib/ConsiderationStructs.sol";

5: import {ReceivedItem, SpentItem} from "@seaport-types/lib/ConsiderationStructs.sol";

6: import {LibString} from "@solady/utils/LibString.sol";

6: import {LibString} from "@solady/utils/LibString.sol";

8: import {ISafe} from "@src/interfaces/ISafe.sol";

8: import {ISafe} from "@src/interfaces/ISafe.sol";

9: import {IHook} from "@src/interfaces/IHook.sol";

9: import {IHook} from "@src/interfaces/IHook.sol";

10: import {ZoneInterface} from "@src/interfaces/IZone.sol";

10: import {ZoneInterface} from "@src/interfaces/IZone.sol";

12: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol";

13: import {toKeycode, toRole} from "@src/libraries/KernelUtils.sol";

13: import {toKeycode, toRole} from "@src/libraries/KernelUtils.sol";

14: import {RentalUtils} from "@src/libraries/RentalUtils.sol";

14: import {RentalUtils} from "@src/libraries/RentalUtils.sol";

15: import {Signer} from "@src/packages/Signer.sol";

15: import {Signer} from "@src/packages/Signer.sol";

16: import {Zone} from "@src/packages/Zone.sol";

16: import {Zone} from "@src/packages/Zone.sol";

17: import {Accumulator} from "@src/packages/Accumulator.sol";

17: import {Accumulator} from "@src/packages/Accumulator.sol";

18: import {Storage} from "@src/modules/Storage.sol";

18: import {Storage} from "@src/modules/Storage.sol";

19: import {PaymentEscrow} from "@src/modules/PaymentEscrow.sol";

19: import {PaymentEscrow} from "@src/modules/PaymentEscrow.sol";

33: } from "@src/libraries/RentalStructs.sol";

33: } from "@src/libraries/RentalStructs.sol";

34: import {Errors} from "@src/libraries/Errors.sol";

34: import {Errors} from "@src/libraries/Errors.sol";

35: import {Events} from "@src/libraries/Events.sol";

35: import {Events} from "@src/libraries/Events.sol";

209:         for (uint256 i; i < offers.length; ++i) {

209:         for (uint256 i; i < offers.length; ++i) {

228:             rentalItems[i + startIndex] = Item({

261:         for (uint256 i; i < offers.length; ++i) {

261:         for (uint256 i; i < offers.length; ++i) {

273:                 totalRentals++;

273:                 totalRentals++;

283:                 totalRentals++;

283:                 totalRentals++;

293:                 totalPayments++;

293:                 totalPayments++;

301:             rentalItems[i + startIndex] = Item({

337:         for (uint256 i; i < considerations.length; ++i) {

337:         for (uint256 i; i < considerations.length; ++i) {

350:             rentalItems[i + startIndex] = Item({

375:         for (uint256 i; i < considerations.length; ++i) {

375:         for (uint256 i; i < considerations.length; ++i) {

381:                 totalPayments++;

381:                 totalPayments++;

385:                 totalRentals++;

385:                 totalRentals++;

417:         items = new Item[](offers.length + considerations.length);

475:         for (uint256 i = 0; i < hooks.length; ++i) {

475:         for (uint256 i = 0; i < hooks.length; ++i) {

567:             for (uint256 i; i < items.length; ++i) {

567:             for (uint256 i; i < items.length; ++i) {

588:                 endTimestamp: block.timestamp + payload.metadata.rentDuration

599:             for (uint256 i = 0; i < items.length; ++i) {

599:             for (uint256 i = 0; i < items.length; ++i) {

695:         for (uint256 i = 0; i < executions.length; ++i) {

695:         for (uint256 i = 0; i < executions.length; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol)

```solidity
File: src/policies/Factory.sol

4: import {SafeL2} from "@safe-contracts/SafeL2.sol";

4: import {SafeL2} from "@safe-contracts/SafeL2.sol";

5: import {SafeProxyFactory} from "@safe-contracts/proxies/SafeProxyFactory.sol";

5: import {SafeProxyFactory} from "@safe-contracts/proxies/SafeProxyFactory.sol";

5: import {SafeProxyFactory} from "@safe-contracts/proxies/SafeProxyFactory.sol";

6: import {TokenCallbackHandler} from "@safe-contracts/handler/TokenCallbackHandler.sol";

6: import {TokenCallbackHandler} from "@safe-contracts/handler/TokenCallbackHandler.sol";

6: import {TokenCallbackHandler} from "@safe-contracts/handler/TokenCallbackHandler.sol";

8: import {ISafe} from "@src/interfaces/ISafe.sol";

8: import {ISafe} from "@src/interfaces/ISafe.sol";

10: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol";

11: import {toKeycode} from "@src/libraries/KernelUtils.sol";

11: import {toKeycode} from "@src/libraries/KernelUtils.sol";

12: import {Errors} from "@src/libraries/Errors.sol";

12: import {Errors} from "@src/libraries/Errors.sol";

13: import {Events} from "@src/libraries/Events.sol";

13: import {Events} from "@src/libraries/Events.sol";

14: import {Storage} from "@src/modules/Storage.sol";

14: import {Storage} from "@src/modules/Storage.sol";

15: import {Stop} from "@src/policies/Stop.sol";

15: import {Stop} from "@src/policies/Stop.sol";

16: import {Guard} from "@src/policies/Guard.sol";

16: import {Guard} from "@src/policies/Guard.sol";

184:                 uint256(keccak256(abi.encode(STORE.totalSafes() + 1, block.chainid)))

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol)

```solidity
File: src/policies/Guard.sol

4: import {BaseGuard} from "@safe-contracts/base/GuardManager.sol";

4: import {BaseGuard} from "@safe-contracts/base/GuardManager.sol";

4: import {BaseGuard} from "@safe-contracts/base/GuardManager.sol";

5: import {Enum} from "@safe-contracts/common/Enum.sol";

5: import {Enum} from "@safe-contracts/common/Enum.sol";

5: import {Enum} from "@safe-contracts/common/Enum.sol";

6: import {LibString} from "@solady/utils/LibString.sol";

6: import {LibString} from "@solady/utils/LibString.sol";

8: import {IHook} from "@src/interfaces/IHook.sol";

8: import {IHook} from "@src/interfaces/IHook.sol";

9: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol";

10: import {toKeycode} from "@src/libraries/KernelUtils.sol";

10: import {toKeycode} from "@src/libraries/KernelUtils.sol";

11: import {Storage} from "@src/modules/Storage.sol";

11: import {Storage} from "@src/modules/Storage.sol";

31: } from "@src/libraries/RentalConstants.sol";

31: } from "@src/libraries/RentalConstants.sol";

32: import {Errors} from "@src/libraries/Errors.sol";

32: import {Errors} from "@src/libraries/Errors.sol";

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol)

```solidity
File: src/policies/Stop.sol

4: import {Enum} from "@safe-contracts/common/Enum.sol";

4: import {Enum} from "@safe-contracts/common/Enum.sol";

4: import {Enum} from "@safe-contracts/common/Enum.sol";

5: import {LibString} from "@solady/utils/LibString.sol";

5: import {LibString} from "@solady/utils/LibString.sol";

7: import {ISafe} from "@src/interfaces/ISafe.sol";

7: import {ISafe} from "@src/interfaces/ISafe.sol";

8: import {IHook} from "@src/interfaces/IHook.sol";

8: import {IHook} from "@src/interfaces/IHook.sol";

10: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol";

11: import {toKeycode} from "@src/libraries/KernelUtils.sol";

11: import {toKeycode} from "@src/libraries/KernelUtils.sol";

12: import {RentalUtils} from "@src/libraries/RentalUtils.sol";

12: import {RentalUtils} from "@src/libraries/RentalUtils.sol";

13: import {Signer} from "@src/packages/Signer.sol";

13: import {Signer} from "@src/packages/Signer.sol";

14: import {Reclaimer} from "@src/packages/Reclaimer.sol";

14: import {Reclaimer} from "@src/packages/Reclaimer.sol";

15: import {Accumulator} from "@src/packages/Accumulator.sol";

15: import {Accumulator} from "@src/packages/Accumulator.sol";

16: import {Storage} from "@src/modules/Storage.sol";

16: import {Storage} from "@src/modules/Storage.sol";

17: import {PaymentEscrow} from "@src/modules/PaymentEscrow.sol";

17: import {PaymentEscrow} from "@src/modules/PaymentEscrow.sol";

18: import {Errors} from "@src/libraries/Errors.sol";

18: import {Errors} from "@src/libraries/Errors.sol";

19: import {Events} from "@src/libraries/Events.sol";

19: import {Events} from "@src/libraries/Events.sol";

28: } from "@src/libraries/RentalStructs.sol";

28: } from "@src/libraries/RentalStructs.sol";

205:         for (uint256 i = 0; i < hooks.length; ++i) {

205:         for (uint256 i = 0; i < hooks.length; ++i) {

276:         for (uint256 i; i < order.items.length; ++i) {

276:         for (uint256 i; i < order.items.length; ++i) {

324:         for (uint256 i = 0; i < orders.length; ++i) {

324:         for (uint256 i = 0; i < orders.length; ++i) {

333:             for (uint256 j = 0; j < orders[i].items.length; ++j) {

333:             for (uint256 j = 0; j < orders[i].items.length; ++j) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol)

### <a name="GAS-4"></a>[GAS-4] Don't initialize variables with default value

*Instances (18)*:

```solidity
File: src/Kernel.sol

566:         for (uint256 i = 0; i < reqLength; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol)

```solidity
File: src/modules/PaymentEscrow.sol

231:         for (uint256 i = 0; i < items.length; ++i) {

341:         for (uint256 i = 0; i < orders.length; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol)

```solidity
File: src/modules/Storage.sol

197:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {

229:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {

249:         for (uint256 i = 0; i < orderHashes.length; ++i) {

260:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol)

```solidity
File: src/packages/Accumulator.sol

120:         for (uint256 i = 0; i < rentalAssetUpdateLength; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol)

```solidity
File: src/packages/Reclaimer.sol

90:         for (uint256 i = 0; i < itemCount; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol)

```solidity
File: src/packages/Signer.sol

170:         for (uint256 i = 0; i < order.items.length; ++i) {

176:         for (uint256 i = 0; i < order.hooks.length; ++i) {

225:         for (uint256 i = 0; i < metadata.hooks.length; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol)

```solidity
File: src/policies/Create.sol

475:         for (uint256 i = 0; i < hooks.length; ++i) {

599:             for (uint256 i = 0; i < items.length; ++i) {

695:         for (uint256 i = 0; i < executions.length; ++i) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol)

```solidity
File: src/policies/Stop.sol

205:         for (uint256 i = 0; i < hooks.length; ++i) {

324:         for (uint256 i = 0; i < orders.length; ++i) {

333:             for (uint256 j = 0; j < orders[i].items.length; ++j) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol)

### <a name="GAS-5"></a>[GAS-5] Functions guaranteed to revert when called by normal users can be marked `payable`

If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as `payable` will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided.

*Instances (21)*:

```solidity
File: src/Kernel.sol

54:     function changeKernel(Kernel newKernel_) external onlyKernel {

106:     function INIT() external virtual onlyKernel {}

192:     function setActiveStatus(bool activate_) external onlyKernel {

277:     function executeAction(Actions action_, address target_) external onlyExecutor {

310:     function grantRole(Role role_, address addr_) public onlyAdmin {

333:     function revokeRole(Role role_, address addr_) public onlyAdmin {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol)

```solidity
File: src/modules/PaymentEscrow.sol

320:     function settlePayment(RentalOrder calldata order) external onlyByProxy permissioned {

380:     function setFee(uint256 feeNumerator) external onlyByProxy permissioned {

397:     function skim(address token, address to) external onlyByProxy permissioned {

420:     function upgrade(address newImplementation) external onlyByProxy permissioned {

429:     function freeze() external onlyByProxy permissioned {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol)

```solidity
File: src/modules/Storage.sol

274:     function addRentalSafe(address safe) external onlyByProxy permissioned {

294:     function updateHookPath(address to, address hook) external onlyByProxy permissioned {

360:     function upgrade(address newImplementation) external onlyByProxy permissioned {

369:     function freeze() external onlyByProxy permissioned {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol)

```solidity
File: src/policies/Admin.sol

126:     function upgradeStorage(address newImplementation) external onlyRole("ADMIN_ADMIN") {

134:     function freezeStorage() external onlyRole("ADMIN_ADMIN") {

154:     function freezePaymentEscrow() external onlyRole("ADMIN_ADMIN") {

164:     function skim(address token, address to) external onlyRole("ADMIN_ADMIN") {

173:     function setFee(uint256 feeNumerator) external onlyRole("ADMIN_ADMIN") {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol)

```solidity
File: src/policies/Guard.sol

362:     function updateHookPath(address to, address hook) external onlyRole("GUARD_ADMIN") {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol)

### <a name="GAS-6"></a>[GAS-6] `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too)

*Saves 5 gas per loop*

*Instances (5)*:

```solidity
File: src/policies/Create.sol

273:                 totalRentals++;

283:                 totalRentals++;

293:                 totalPayments++;

381:                 totalPayments++;

385:                 totalRentals++;

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol)

### <a name="GAS-7"></a>[GAS-7] Use != 0 instead of > 0 for unsigned integer comparison

*Instances (5)*:

```solidity
File: src/policies/Create.sol

433:             if (considerations.length > 0) {

442:             if (offers.length > 0) {

606:             if (payload.metadata.hooks.length > 0) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol)

```solidity
File: src/policies/Stop.sol

288:         if (order.hooks.length > 0) {

348:             if (orders[i].hooks.length > 0) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol)

## Low Issues

| |Issue|Instances|
|-|:-|:-:|
| [L-1](#L-1) |  `abi.encodePacked()` should not be used with dynamic types when passing the result to a hash function such as `keccak256()` | 3 |
| [L-2](#L-2) | Empty Function Body - Consider commenting why | 16 |
| [L-3](#L-3) | Initializers could be front-run | 2 |

### <a name="L-1"></a>[L-1]  `abi.encodePacked()` should not be used with dynamic types when passing the result to a hash function such as `keccak256()`

Use `abi.encode()` instead which will pad items to 32 bytes, which will [prevent hash collisions](https://docs.soliditylang.org/en/v0.8.13/abi-spec.html#non-standard-packed-mode) (e.g. `abi.encodePacked(0x123,0x456)` => `0x123456` => `abi.encodePacked(0x1,0x23456)`, but `abi.encode(0x123,0x456)` => `0x0...1230...456`). "Unless there is a compelling reason, `abi.encode` should be preferred". If there is only one argument to `abi.encodePacked()` it can often be cast to `bytes()` or `bytes32()` [instead](https://ethereum.stackexchange.com/questions/30912/how-to-compare-strings-in-solidity#answer-82739).
If all arguments are strings and or bytes, `bytes.concat()` should be used instead

*Instances (3)*:

```solidity
File: src/packages/Signer.sol

186:                     keccak256(abi.encodePacked(itemHashes)),

187:                     keccak256(abi.encodePacked(hookHashes)),

236:                     keccak256(abi.encodePacked(hookHashes))

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol)

### <a name="L-2"></a>[L-2] Empty Function Body - Consider commenting why

*Instances (16)*:

```solidity
File: src/Kernel.sol

71:     constructor(Kernel kernel_) KernelAdapter(kernel_) {}

100:     function VERSION() external pure virtual returns (uint8 major, uint8 minor) {}

106:     function INIT() external virtual onlyKernel {}

124:     constructor(Kernel kernel_) KernelAdapter(kernel_) {}

153:     {}

172:     {}

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol)

```solidity
File: src/modules/PaymentEscrow.sol

51:     constructor(Kernel kernel_) Module(kernel_) {}

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol)

```solidity
File: src/modules/Storage.sol

79:     constructor(Kernel kernel_) Module(kernel_) {}

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol)

```solidity
File: src/policies/Admin.sol

29:     constructor(Kernel kernel_) Policy(kernel_) {}

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol)

```solidity
File: src/policies/Create.sol

61:     constructor(Kernel kernel_) Policy(kernel_) Signer() Zone() {}

504:             {} catch Error(string memory revertReason) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol)

```solidity
File: src/policies/Guard.sol

52:     constructor(Kernel kernel_) Policy(kernel_) {}

167:         try IHook(hook).onTransaction(safe, to, value, data) {} catch Error(

353:     function checkAfterExecution(bytes32 txHash, bool success) external override {}

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol)

```solidity
File: src/policies/Stop.sol

52:     constructor(Kernel kernel_) Policy(kernel_) Signer() Reclaimer() {}

234:             {} catch Error(string memory revertReason) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol)

### <a name="L-3"></a>[L-3] Initializers could be front-run

Initializers could be front-run, allowing an attacker to either set their own values, take ownership of the contract, and in the best case forcing a re-deployment

*Instances (2)*:

```solidity
File: src/policies/Factory.sol

155:         bytes memory initializerPayload = abi.encodeCall(

183:                 initializerPayload,

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol)

## Medium Issues

| |Issue|Instances|
|-|:-|:-:|
| [M-1](#M-1) | Centralization Risk for trusted owners | 12 |

### <a name="M-1"></a>[M-1] Centralization Risk for trusted owners

#### Impact

Contracts have owners with privileged rights to perform admin tasks and need to be trusted to not perform malicious updates or drain funds.

*Instances (12)*:

```solidity
File: src/Kernel.sol

130:     modifier onlyRole(bytes32 role_) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol)

```solidity
File: src/policies/Admin.sol

102:     ) external onlyRole("ADMIN_ADMIN") {

116:     ) external onlyRole("ADMIN_ADMIN") {

126:     function upgradeStorage(address newImplementation) external onlyRole("ADMIN_ADMIN") {

134:     function freezeStorage() external onlyRole("ADMIN_ADMIN") {

146:     ) external onlyRole("ADMIN_ADMIN") {

154:     function freezePaymentEscrow() external onlyRole("ADMIN_ADMIN") {

164:     function skim(address token, address to) external onlyRole("ADMIN_ADMIN") {

173:     function setFee(uint256 feeNumerator) external onlyRole("ADMIN_ADMIN") {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol)

```solidity
File: src/policies/Create.sol

735:     ) external override onlyRole("SEAPORT") returns (bytes4 validOrderMagicValue) {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol)

```solidity
File: src/policies/Guard.sol

362:     function updateHookPath(address to, address hook) external onlyRole("GUARD_ADMIN") {

376:     ) external onlyRole("GUARD_ADMIN") {

```

[Link to code](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol)
