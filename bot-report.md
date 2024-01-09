# Winning bot race submission
 This is the top-ranked automated findings report, from LightChaser bot. All findings in this report will be considered known issues for the purposes of your C4 audit.
 
 LightChaser-V3

 ## Summary

 | |Issue|Instances| Gas Savings
 |-|:-|:-:|:-:|
| [[M-01](#m-01)] | Privileged functions can create points of failure | 14| 0|
| [[M-02](#m-02)] | Return of create2 is not checked | 1| 0|
| [[L-01](#l-01)] | Potential division by zero should have zero checks in place  | 1| 0|
| [[L-02](#l-02)] | Missing checks for address(0x0) when updating address state variables  | 1| 0|
| [[L-03](#l-03)] | Low Level Calls to Custom Addresses | 1| 0|
| [[L-04](#l-04)] | Contract can't receive NFTs sent with safeTransferFrom method | 1| 0|
| [[L-05](#l-05)] | Function calls within for loops | 11| 0|
| [[L-06](#l-06)] | For loops in public or external functions should be avoided due to high gas costs and possible DOS | 3| 0|
| [[L-07](#l-07)] | Missing zero address check in constructor | 1| 0|
| [[L-08](#l-08)] | Using zero as a parameter | 1| 0|
| [[L-09](#l-09)] | Critical functions should be a two step procedure | 3| 0|
| [[L-10](#l-10)] | Arrays can grow in size without a way to shrink them | 1| 0|
| [[L-11](#l-11)] | Revert on Transfer to the Zero Address | 1| 0|
| [[L-12](#l-12)] | Sweeping may break accounting if tokens with multiple addresses are used | 1| 0|
| [[L-13](#l-13)] | Missing zero address check in initializer | 1| 0|
| [[L-14](#l-14)] | Critical functions should have a timelock | 1| 0|
| [[L-15](#l-15)] | Unbounded loop may run out of gas | 17| 0|
| [[L-16](#l-16)] | Mapping arrays can grow in size without a way to shrink them | 1| 0|
| [[L-17](#l-17)] | Consider implementing two-step procedure for updating protocol addresses | 1| 0|
| [[L-18](#l-18)] | Unbounded state array which is iterated upon | 2| 0|
| [[L-19](#l-19)] | External calls in modifiers should be avoided | 2| 0|
| [[L-20](#l-20)] | Prefer skip over revert model in iteration | 3| 0|
| [[L-21](#l-21)] | Address collision possible due to upcast | 1| 0|
| [[L-22](#l-22)] | Use of abi.encodePacked with dynamic types inside keccak256 | 2| 0|
| [[L-23](#l-23)] | Constructors missing validation | 3| 0|
| [[L-24](#l-24)] | Functions calling contracts/addresses with transfer hooks are missing reentrancy guards | 3| 0|
| [[L-25](#l-25)] | Inconsistent checks of address params against address(0) | 1| 0|
| [[L-26](#l-26)] | Upgradeable contract uses non-upgradeable version of the OpenZeppelin libraries/contracts | 4| 0|
| [[L-27](#l-27)] | Functions calling contracts/addresses with transfer hooks are missing reentrancy guards | 3| 0|
| [[L-28](#l-28)] | Upgradable contracts not taken into account | 1| 0|
| [[G-01](#g-01)] | Consider merging sequential for loops  | 1| 0|
| [[G-02](#g-02)] | Lack of unchecked in loops  | 18| 1560|
| [[G-03](#g-03)] | Multiple accesses of the same mapping/array key/index should be cached  | 1| 294|
| [[G-04](#g-04)] | Shorten the array rather than copying to a new one  | 12| 0|
| [[G-05](#g-05)] | Using bools for storage incurs overhead  | 5| 560|
| [[G-06](#g-06)] | Low level call can be optimized with assembly | 1| 0|
| [[G-07](#g-07)] | Optimize by Using Assembly for Low-Level Calls' Return Data | 1| 159|
| [[G-08](#g-08)] | Public functions not used internally can be marked as external to save gas | 3| 0|
| [[G-09](#g-09)] | Calldata should be used in place of memory function parameters when not mutated | 1| 13|
| [[G-10](#g-10)] | Nested for loops should be avoided due to high gas costs resulting from O^2 time complexity | 1| 0|
| [[G-11](#g-11)] | Usage of smaller uint/int types causes overhead | 5| 275|
| [[G-12](#g-12)] | Use != 0 instead of > 0 | 5| 15|
| [[G-13](#g-13)] | Integer increments by one can be unchecked to save on gas fees | 24| 2880|
| [[G-14](#g-14)] | Use byte32 in place of string | 5| 0|
| [[G-15](#g-15)] | Default bool values are manually reset | 1| 0|
| [[G-16](#g-16)] | Default int values are manually reset | 1| 0|
| [[G-17](#g-17)] | <= or >= is more efficient than < or >  | 2| 6|
| [[G-18](#g-18)] | Use assembly to check for the zero address | 4| 0|
| [[G-19](#g-19)] | Divisions which do not divide by -X cannot overflow or overflow so such operations can be unchecked to save gas | 2| 0|
| [[G-20](#g-20)] | Consider activating via-ir for deploying | 1| 250|
| [[G-21](#g-21)] | Expression ("") is cheaper than new bytes(0) | 2| 518|
| [[G-22](#g-22)] | Add unchecked {} for subtractions where the operands cannot underflow | 8| 680|
| [[G-23](#g-23)] | Private functions used once can be inlined | 4| 0|
| [[G-24](#g-24)] | Use bitmap to save gas | 7| 490|
| [[G-25](#g-25)] | Use assembly hashing | 10| 0|
| [[G-26](#g-26)] | Consider using OZ EnumerateSet in place of nested mappings | 3| 3000|
| [[G-27](#g-27)] | Use assembly to emit events | 8| 304|
| [[G-28](#g-28)] | Use solady library where possible to save gas | 3| 3000|
| [[G-29](#g-29)] | Use assembly in place of abi.decode to extract calldata values more efficiently | 2| 0|
| [[G-30](#g-30)] | Counting down in for statements is more gas efficient | 18| 0|
| [[G-31](#g-31)] | Identical Deployments Should be Replaced with Clone | 1| 0|
| [[G-32](#g-32)] | Redundant Contract Existence Check in Consecutive External Calls | 1| 400|
| [[G-33](#g-33)] | Mark Functions That Revert For Normal Users As payable | 13| 325|
| [[G-34](#g-34)] | State variable read in a loop | 1| 9|
| [[G-35](#g-35)] | Function names can be optimized | 11| 1408|
| [[G-36](#g-36)] | Assembly let var only used on once | 1| 0|
| [[G-37](#g-37)] | Use assembly to validate msg.sender | 6| 0|
| [[G-38](#g-38)] | Simple checks for zero uint can be done using assembly to save gas | 8| 48|
| [[G-39](#g-39)] | Trade-offs Between Modifiers and Internal Functions | 52| 546000|
| [[G-40](#g-40)] | Using nested if to save gas | 5| 30|
| [[G-41](#g-41)] | Optimize Deployment Size by Fine-tuning IPFS Hash | 11| 116600|
| [[G-42](#g-42)] | Avoid Unnecessary Public Variables | 16| 352000|
| [[G-43](#g-43)] | Avoid emitting event on every iteration | 1| 375|
| [[G-44](#g-44)] | Inline modifiers used only once | 1| 0|
| [[G-45](#g-45)] | Use s.x = s.x + y instead of s.x += y for memory structs (same for -= etc) | 4| 400|
| [[G-46](#g-46)] | ++X costs slightly less gas than X++ (same with --) | 4| 20|
| [[G-47](#g-47)] | Variable declared within iteration | 5| 0|
| [[G-48](#g-48)] | The use of a logical AND in place of double if is slightly less gas efficient in instances where there isn't a corresponding else statement for the given if statement | 6| 90|
| [[G-49](#g-49)] | Calling .length in a for loop wastes gas | 12| 1358|
| [[G-50](#g-50)] | Internal functions only used once can be inlined so save gas | 32| 960|
| [[G-51](#g-51)] | Constructors can be marked as payable to save deployment gas | 10| 0|
| [[G-52](#g-52)] | Use assembly scratch space to build calldata for external calls | 101| 22220|
| [[G-53](#g-53)] | Use assembly scratch space to build calldata for event emits | 5| 1100|
| [[G-54](#g-54)] | Consider using solady's "FixedPointMathLib" | 2| 0|
| [[G-55](#g-55)] | Same cast is done multiple times | 1| 0|
| [[G-56](#g-56)] | Assigning to structs can be more efficient | 5| 650|
| [[G-57](#g-57)] | Cache address(this) when used more than once | 2| 0|
| [[G-58](#g-58)] | bytes.concat() can be used in place of abi.encodePacked | 7| 0|
| [[G-59](#g-59)] | Empty functions should be removed to save gas | 5| 0|
| [[N-01](#n-01)] | Assembly block creates dirty bits  | 1| 0|
| [[N-02](#n-02)] | Cyclomatic complexity in functions  | 2| 0|
| [[N-03](#n-03)] | Code does not follow the best practice of check-effects-interaction  | 1| 0|
| [[N-04](#n-04)] | Events may be emitted out of order due to code not follow the best practice of check-effects-interaction  | 1| 0|
| [[N-05](#n-05)] | For extended 'using-for' usage, use the latest pragma version  | 4| 0|
| [[N-06](#n-06)] | .call bypasses function existence check, type checking and argument packing  | 1| 0|
| [[N-07](#n-07)] | Double type casts create complexity within the code  | 1| 0|
| [[N-08](#n-08)] | Inconsistent comment spacing  | 1| 0|
| [[N-09](#n-09)] | Consider adding emergency-stop functionality  | 11| 0|
| [[N-10](#n-10)] | Employ Explicit Casting to Bytes or Bytes32 for Enhanced Code Clarity and Meaning  | 4| 0|
| [[N-11](#n-11)] | Missing events in sensitive functions  | 7| 0|
| [[N-12](#n-12)] | The call abi.encodeWithSelector is not type safe | 2| 0|
| [[N-13](#n-13)] | Floating pragma should be avoided | 1| 0|
| [[N-14](#n-14)] | Empty function blocks | 5| 0|
| [[N-15](#n-15)] | In functions which accept an address as a parameter, there should be a zero address check to prevent bugs | 46| 0|
| [[N-16](#n-16)] | Enum values should be used in place of constant array indexes | 19| 0|
| [[N-17](#n-17)] | Default int values are manually set | 15| 0|
| [[N-18](#n-18)] | Revert statements within external and public functions can be used to perform DOS attacks | 13| 0|
| [[N-19](#n-19)] | Functions which are either private or internal should have a preceding _ in their name | 1| 0|
| [[N-20](#n-20)] | Private and internal state variables should have a preceding _ in their name unless they are constants | 1| 0|
| [[N-21](#n-21)] | Contract lines should not be longer than 120 characters for readability | 2| 0|
| [[N-22](#n-22)] | Setters should prevent re-setting of the same value | 3| 2400|
| [[N-23](#n-23)] | Function names should differ to make the code more readable | 18| 0|
| [[N-24](#n-24)] | Functions within contracts are not ordered according to the solidity style guide | 5| 0|
| [[N-25](#n-25)] | Use SafeCast to safely downcast variables | 6| 0|
| [[N-26](#n-26)] | Functions which set address state variables should have zero address checks | 3| 0|
| [[N-27](#n-27)] | Interface imports should be declared first | 4| 0|
| [[N-28](#n-28)] | A function which defines named returns in it's declaration doesn't need to use return  | 1| 0|
| [[N-29](#n-29)] | Use allowlist/denylist rather than whitelist/blacklist | 16| 0|
| [[N-30](#n-30)] | Multiple mappings can be replaced with a single struct mapping | 2| 0|
| [[N-31](#n-31)] | Constants should be on the left side of the  | 16| 0|
| [[N-32](#n-32)] | Defined named returns not used within function  | 2| 0|
| [[N-33](#n-33)] | Both immutable and constant state variables should be CONSTANT_CASE | 7| 0|
| [[N-34](#n-34)] | Consider using named mappings | 6| 0|
| [[N-35](#n-35)] | Uses of EIP712 does not include a salt | 1| 0|
| [[N-36](#n-36)] | Loss of precision | 1| 0|
| [[N-37](#n-37)] | Use a single contract or library for system wide constants | 1| 0|
| [[N-38](#n-38)] | Consider using modifiers for address control | 1| 0|
| [[N-39](#n-39)] | Default address(0) can be returned | 3| 0|
| [[N-40](#n-40)] | Variables should be used in place of magic numbers to improve readability | 5| 0|
| [[N-41](#n-41)] | Long powers of ten should use scientific notation 1eX | 4| 0|
| [[N-42](#n-42)] | Use EIP-5767 to manage EIP712 domains | 1| 0|
| [[N-43](#n-43)] | Overridden function has no body | 1| 0|
| [[N-44](#n-44)] | Empty bytes check is missing | 12| 0|
| [[N-45](#n-45)] | Consider adding a time delay to upgrade implementation functions | 3| 0|
| [[N-46](#n-46)] | Use scopes sparingly | 1| 0|
| [[N-47](#n-47)] | No equate comparison checks between to and from address parameters | 1| 0|
| [[N-48](#n-48)] | Do not use underscore at the end of variable name | 7| 0|
| [[N-49](#n-49)] | Consider using SMTChecker | 12| 3000|
| [[N-50](#n-50)] | Contracts should have full test coverage | 11| 0|
| [[N-51](#n-51)] | Consider using named function calls | 25| 0|
| [[N-52](#n-52)] | Using XOR (^) and AND (&) bitwise equivalents | 2| 0|
| [[N-53](#n-53)] | Lack Of Brace Spacing | 43| 0|
| [[N-54](#n-54)] | Common functions should be refactored to a common base contract | 6| 0|
| [[N-55](#n-55)] | Use of override is unnecessary | 1| 0|
| [[N-56](#n-56)] | If statement control structures do not comply with best practices | 16| 0|
| [[N-57](#n-57)] | Consider adding formal verification proofs | 11| 0|
| [[N-58](#n-58)] | Use string.concat() on strings instead of abi.encodePacked() for clearer semantic meaning | 4| 0|
| [[N-59](#n-59)] | function names should be lowerCamelCase | 5| 0|
| [[N-60](#n-60)] | Consider bounding input array length | 15| 0|
| [[N-61](#n-61)] | Consider implementing EIP-5267 to securely describe EIP-712 domains being used | 1| 0|
| [[N-62](#n-62)] | Add inline comments for unnamed variables in function declarations | 1| 0|
| [[N-63](#n-63)] | Public state arrays should have a getter to return all elements | 1| 0|
| [[N-64](#n-64)] | Ensure block.timestamp is only used in long time intervals | 1| 0|
| [[N-65](#n-65)] | Don't use assembly for create2 | 1| 0|
| [[N-66](#n-66)] | It is best practice to use linear inheritance | 5| 0|
| [[N-67](#n-67)] | Contracts with only unimplemented functions can be labeled as abstract | 3| 0|
| [[N-68](#n-68)] | A event should be emitted if a non immutable state variable is set in a constructor | 2| 0|
| [[N-69](#n-69)] | Consider only defining one library/interface/contract per sol file | 3| 0|
| [[N-70](#n-70)] | Immutable and constant integer state variables should not be casted | 1| 0|
| [[N-71](#n-71)] | Numbers downcast to addresses may result in collisions | 1| 0|
| [[N-72](#n-72)] | Public variable declarations should have NatSpec descriptions | 2| 0|
| [[N-73](#n-73)] | Use the Modern Upgradeable Contract Paradigm | 11| 0|
| [[N-74](#n-74)] | Upgrade openzeppelin to the Latest Version - 5.0.0 | 4| 0|
| [[N-75](#n-75)] | Use a struct to encapsulate multiple function parameters | 5| 0|
| [[N-76](#n-76)] | Returning a struct instead of returning many variables is better | 1| 0|
| [[N-77](#n-77)] | Long numbers should include underscores to improve readability and prevent typos | 2| 0|
| [[N-78](#n-78)] | Consider using a format prettier or forge fmt | 1| 0|
| [[N-79](#n-79)] | Avoid defining a function in a single line including it's contents | 1| 0|
| [[N-80](#n-80)] | Use 'using' keyword when using specific imports rather than calling the specific import directly | 99| 0|
| [[N-81](#n-81)] | Try catch statement without human readable error | 4| 0|
| [[N-82](#n-82)] | Try catch statement with declared Error consumes more gas | 3| 0|
| [[N-83](#n-83)] | Avoid declaring variables with the names of defined functions within the project | 2| 0|
| [[N-84](#n-84)] | Reserved keyword 'error' used as a variable/object name | 2| 0|
| [[N-85](#n-85)] | Avoid caching global vars used once within the function | 1| 12|
| [[N-86](#n-86)] | All verbatim blocks are considered identical by deduplicator and can incorrectly be unified | 1| 0|
| [[N-87](#n-87)] | ERC777 tokens can introduce reentrancy risks | 2| 0|
| [[N-88](#n-88)] | Add inline comments for unnamed variables in function declarations | 1| 0|
| [[N-89](#n-89)] | Public variable declarations should have NatSpec descriptions | 2| 0|
| [[N-90](#n-90)] | No @inheritdoc on override functions | 5| 0|
| [[N-91](#n-91)] | Natspec @author is missing from contract | 11| 0|
| [[N-92](#n-92)] | Natspec @dev is missing from contract | 11| 0|
| [[N-93](#n-93)] | Natspec @author is missing from abstract | 6| 0|
| [[N-94](#n-94)] | Natspec @dev is missing from abstract | 6| 0|
| [[N-95](#n-95)] | Natspec @params comments are missing from modifier | 1| 0|
| [[N-96](#n-96)] | Natspec @notice comments are missing from modifier | 5| 0|
| [[N-97](#n-97)] | Natspec @dev comments are missing from function | 56| 0|
| [[N-98](#n-98)] | Natspec @notice comments are missing from function | 57| 0|
| [[N-99](#n-99)] | Natspec @notice comments are missing from constructor | 9| 0|
| [[N-100](#n-100)] | Natspec comments are missing from scope blocks | 1| 0|
| [[N-101](#n-101)] | Natspec comments are missing from assembly blocks | 6| 0|
| [[D-01](#d-01)] | Gas grief possible on unsafe external calls [EXP] | 1| 0|
| [[D-02](#d-02)] | Function with two array parameter missing a length check [EXP] | 1| 0|
| [[D-03](#d-03)] | Code does not follow the best practice of check-effects-interaction [EXP] | 3| 0|
| [[D-04](#d-04)] | Events may be emitted out of order due to code not follow the best practice of check-effects-interaction [EXP] | 1| 0|
| [[D-05](#d-05)] | Consider merging sequential for loops [EXP] | 4| 0|
| [[D-06](#d-06)] | Avoid updating storage when the value hasn't changed [EXP] | 1| 800|
| [[D-07](#d-07)] | Multiple accesses of the same mapping/array key/index should be cached [EXP] | 6| 294|
| [[D-08](#d-08)] | The result of a function call should be cached rather than re-calling the function [EXP-0] | 1| 100|
| [[D-09](#d-09)] | Non constant/immutable state variables are missing a setter post deployment [EXP-1] | 1| 0|
| [[D-10](#d-10)] | State variables used within a function more than once should be cached to save gas [EXP-1] | 2| 200|
| [[D-11](#d-11)] | Using abi.encodePacked can result in hash collision when used in hashing functions [EXP-2] | 5| 0|
| [[D-12](#d-12)] | Getting a bool return value does not confirm the existence of a function in an external call [EXP-2] | 2| 0|
| [[D-13](#d-13)] | No limits when setting fees [EXP-3] | 2| 0|
| [[D-14](#d-14)] | Employ Explicit Casting to Bytes or Bytes32 for Enhanced Code Clarity and Meaning [EXP-3] | 1| 0|
| [[D-15](#d-15)] | Use assembly to write address storage values [EXP-3] | 1| 74|
| [[D-16](#d-16)] | Using bools for storage incurs overhead [EXP-3] | 3| 560|
| [[D-17](#d-17)] | Loss of precision | 1| 0|
| [[D-18](#d-18)] | For loops in public or external functions should be avoided due to high gas costs and possible DOS | 4| 0|


 LightChaser-V3 ### Medium Risk Issues


### [M-01]<a name="m-01"></a> Privileged functions can create points of failure
Ensure such accounts are protected and consider implementing multi sig to prevent a single point of failure

*There are 14 instance(s) of this issue:*

```solidity
310:     function grantRole(Role role_, address addr_) public onlyAdmin  // <= FOUND

```


*GitHub* : [310](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L310-L310)

```solidity
333:     function revokeRole(Role role_, address addr_) public onlyAdmin  // <= FOUND

```


*GitHub* : [333](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L333-L333)

```solidity
99:     function toggleWhitelistDelegate(
100:         address delegate,
101:         bool isEnabled
102:     ) external onlyRole("ADMIN_ADMIN")  // <= FOUND

```


*GitHub* : [102](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L102-L102)

```solidity
113:     function toggleWhitelistExtension(
114:         address extension,
115:         bool isEnabled
116:     ) external onlyRole("ADMIN_ADMIN")  // <= FOUND

```


*GitHub* : [116](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L116-L116)

```solidity
126:     function upgradeStorage(address newImplementation) external onlyRole("ADMIN_ADMIN")  // <= FOUND

```


*GitHub* : [126](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L126-L126)

```solidity
134:     function freezeStorage() external onlyRole("ADMIN_ADMIN")  // <= FOUND

```


*GitHub* : [134](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L134-L134)

```solidity
144:     function upgradePaymentEscrow(
145:         address newImplementation
146:     ) external onlyRole("ADMIN_ADMIN")  // <= FOUND

```


*GitHub* : [146](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L146-L146)

```solidity
154:     function freezePaymentEscrow() external onlyRole("ADMIN_ADMIN")  // <= FOUND

```


*GitHub* : [154](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L154-L154)

```solidity
164:     function skim(address token, address to) external onlyRole("ADMIN_ADMIN")  // <= FOUND

```


*GitHub* : [164](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L164-L164)

```solidity
173:     function setFee(uint256 feeNumerator) external onlyRole("ADMIN_ADMIN")  // <= FOUND

```


*GitHub* : [173](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L173-L173)

```solidity
733:     function validateOrder(
734:         ZoneParameters calldata zoneParams
735:     ) external override onlyRole("SEAPORT") returns (bytes4 validOrderMagicValue)  // <= FOUND

```


*GitHub* : [735](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L735-L735)

```solidity
362:     function updateHookPath(address to, address hook) external onlyRole("GUARD_ADMIN")  // <= FOUND

```


*GitHub* : [362](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L362-L362)

```solidity
373:     function updateHookStatus(
374:         address hook,
375:         uint8 bitmap
376:     ) external onlyRole("GUARD_ADMIN")  // <= FOUND

```


*GitHub* : [376](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L376-L376)

```solidity
733:     function validateOrder(
734:         ZoneParameters calldata zoneParams
735:     ) external override onlyRole("SEAPORT") returns (bytes4 validOrderMagicValue) { // <= FOUND
736:         
737:         (RentPayload memory payload, bytes memory signature) = abi.decode(
738:             zoneParams.extraData,
739:             (RentPayload, bytes)
740:         );
741: 
742:         
743:         SeaportPayload memory seaportPayload = SeaportPayload({
744:             orderHash: zoneParams.orderHash,
745:             zoneHash: zoneParams.zoneHash,
746:             offer: zoneParams.offer,
747:             consideration: zoneParams.consideration,
748:             totalExecutions: zoneParams.totalExecutions,
749:             fulfiller: zoneParams.fulfiller,
750:             offerer: zoneParams.offerer
751:         });
752: 
753:         
754:         _validateProtocolSignatureExpiration(payload.expiration);
755: 
756:         
757:         _validateFulfiller(payload.intendedFulfiller, seaportPayload.fulfiller);
758: 
759:         
760:         address signer = _recoverSignerFromPayload(
761:             _deriveRentPayloadHash(payload),
762:             signature
763:         );
764: 
765:         
766:         if (!kernel.hasRole(signer, toRole("CREATE_SIGNER"))) { // <= FOUND
767:             revert Errors.CreatePolicy_UnauthorizedCreatePolicySigner();
768:         }
769: 
770:         
771:         _rentFromZone(payload, seaportPayload);
772: 
773:         
774:         validOrderMagicValue = ZoneInterface.validateOrder.selector;
775:     }

```


*GitHub* : [735](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L735-L766)
### [M-02]<a name="m-02"></a> Return of create2 is not checked
In the assembly block, once the contract creation is initiated using CREATE2, it returns an address. This address is then compared to the zero address. If the returned address is the zero address, it means the contract creation has failed. This is a critical step to validate the success of contract creation and ensures that the smart contract behaves correctly even in the event of contract creation failure. This is essential to ensure proxy calls are not made to an non existent contract

*There are 1 instance(s) of this issue:*

```solidity
32:     function deploy(
33:         bytes32 salt,
34:         bytes memory initCode
35:     ) external payable returns (address deploymentAddress) {
36:         
37:         if (address(bytes20(salt)) != msg.sender) {
38:             revert Errors.Create2Deployer_UnauthorizedSender(msg.sender, salt);
39:         }
40: 
41:         
42:         address targetDeploymentAddress = getCreate2Address(salt, initCode);
43: 
44:         
45:         if (deployed[targetDeploymentAddress]) {
46:             revert Errors.Create2Deployer_AlreadyDeployed(targetDeploymentAddress, salt);
47:         }
48: 
49:         
50:         deployed[targetDeploymentAddress] = true;
51: 
52:         
53:         assembly {
54:             deploymentAddress := create2( // <= FOUND
55:                 
56:                 callvalue(),
57:                 
58:                 add(initCode, 0x20),
59:                 
60:                 mload(initCode),
61:                 
62:                 salt
63:             )
64:         }
65: 
66:         
67:         if (deploymentAddress != targetDeploymentAddress) {
68:             revert Errors.Create2Deployer_MismatchedDeploymentAddress(
69:                 targetDeploymentAddress,
70:                 deploymentAddress
71:             );
72:         }
73:     }

```


*GitHub* : [32](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L32-L54)### Low Risk Issues


### [L-01]<a name="l-01"></a> Potential division by zero should have zero checks in place 
Implement a zero address check for found instances

*There are 1 instance(s) of this issue:*

```solidity
132:     function _calculatePaymentProRata(
133:         uint256 amount,
134:         uint256 elapsedTime,
135:         uint256 totalTime
136:     ) internal pure returns (uint256 renterAmount, uint256 lenderAmount) {
137:         
138:         uint256 numerator = (amount * elapsedTime) * 1000;
139: 
140:         
141:         
142:         renterAmount = ((numerator / totalTime) + 500) / 1000;
143: 
144:         
145:         lenderAmount = amount - renterAmount;
146:     }

```


*GitHub* : [132](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L132-L132)
### [L-02]<a name="l-02"></a> Missing checks for address(0x0) when updating address state variables

*There are 1 instance(s) of this issue:*

```solidity
277:     function executeAction(Actions action_, address target_) external onlyExecutor {
278:         if (action_ == Actions.InstallModule) {
279:             ensureContract(target_);
280:             ensureValidKeycode(Module(target_).KEYCODE());
281:             _installModule(Module(target_));
282:         } else if (action_ == Actions.UpgradeModule) {
283:             ensureContract(target_);
284:             ensureValidKeycode(Module(target_).KEYCODE());
285:             _upgradeModule(Module(target_));
286:         } else if (action_ == Actions.ActivatePolicy) {
287:             ensureContract(target_);
288:             _activatePolicy(Policy(target_));
289:         } else if (action_ == Actions.DeactivatePolicy) {
290:             ensureContract(target_);
291:             _deactivatePolicy(Policy(target_));
292:         } else if (action_ == Actions.MigrateKernel) {
293:             ensureContract(target_);
294:             _migrateKernel(Kernel(target_));
295:         } else if (action_ == Actions.ChangeExecutor) {
296:             executor = target_; // <= FOUND
297:         } else if (action_ == Actions.ChangeAdmin) {
298:             admin = target_; // <= FOUND
299:         }
300: 
301:         emit Events.ActionExecuted(action_, target_);
302:     }

```


*GitHub* : [277](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L277-L298)
### [L-03]<a name="l-03"></a> Low Level Calls to Custom Addresses
Low-level calls (such as `.call()`, `.delegatecall()`, or `.callcode()`) in Solidity provide a way to interact with other contracts or addresses. However, when these calls are made to addresses that are provided as parameters or are not well-validated, they pose a significant security risk. Untrusted addresses might contain malicious code leading to unexpected behavior, loss of funds, or vulnerabilities.

**Resolution**: Prefer using high-level Solidity function calls or interface-based interactions with known contracts to ensure security. If low-level calls are necessary, rigorously validate the addresses and test all possible interactions. Implementing additional checks and fail-safes can help mitigate potential risks associated with low-level calls.

*There are 1 instance(s) of this issue:*

```solidity
100:     function _safeTransfer(address token, address to, uint256 value) internal { // <= FOUND
101:         
102:         (bool success, bytes memory data) = token.call( // <= FOUND
103:             abi.encodeWithSelector(IERC20.transfer.selector, to, value)
104:         );
105: 
106:         
107:         
108:         
109:         
110:         
111:         
112:         
113:         
114:         
115:         if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
116:             revert Errors.PaymentEscrowModule_PaymentTransferFailed(token, to, value);
117:         }
118:     }

```


*GitHub* : [100](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L100-L102)
### [L-04]<a name="l-04"></a> Contract can't receive NFTs sent with safeTransferFrom method
The contract under consideration is designed to receive and store ERC721 tokens. However, certain smart wallets or contracts might utilize the `safeTransferFrom` method to send an NFT. The `safeTransferFrom` method checks for the implementation of the `onERC721Received` method when the recipient is a contract. This is to ensure that the recipient contract can appropriately handle ERC721 tokens. Therefore, it's essential for the contract to extend the `ERC721Holder` contract from OpenZeppelin. The `ERC721Holder` contract has the `onERC721Received` method implemented, which allows the contract to correctly receive and store ERC721 tokens sent using `safeTransferFrom`.

*There are 1 instance(s) of this issue:*

```solidity
41: contract Create is Policy, Signer, Zone, Accumulator 

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L41-L41)
### [L-05]<a name="l-05"></a> Function calls within for loops
Making function calls or external calls within loops in Solidity can lead to inefficient gas usage, potential bottlenecks, and increased vulnerability to attacks. Each function call or external call consumes gas, and when executed within a loop, the gas cost multiplies, potentially causing the transaction to run out of gas or exceed block gas limits. This can result in transaction failure or unpredictable behavior.

*There are 11 instance(s) of this issue:*

```solidity
231:        for (uint256 i = 0; i < items.length; ++i) {
232:             
233:             Item memory item = items[i];
234: 
235:             
236:             if (item.isERC20()) {
237:                 
238:                 
239:                 uint256 paymentAmount = item.amount;
240: 
241:                 
242:                 if (fee != 0) {
243:                     
244:                     uint256 paymentFee = _calculateFee(paymentAmount); // <= FOUND
245: 
246:                     
247:                     paymentAmount -= paymentFee;
248:                 }
249: 
250:                 
251:                 
252:                 _decreaseDeposit(item.token, item.amount); // <= FOUND
253: 
254:                 
255:                 if (orderType.isPayOrder() && !isRentalOver) {
256:                     
257:                     _settlePaymentProRata( // <= FOUND
258:                         item.token,
259:                         paymentAmount,
260:                         lender,
261:                         renter,
262:                         elapsedTime,
263:                         totalTime
264:                     );
265:                 }
266:                 
267:                 else if (
268:                     (orderType.isPayOrder() && isRentalOver) || orderType.isBaseOrder()
269:                 ) {
270:                     
271:                     _settlePaymentInFull( // <= FOUND
272:                         item.token,
273:                         paymentAmount,
274:                         item.settleTo,
275:                         lender,
276:                         renter
277:                     );
278:                 } else {
279:                     revert Errors.Shared_OrderTypeNotSupported(uint8(orderType));
280:                 }

```


*GitHub* : [231](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L231-L271)

```solidity
341:        for (uint256 i = 0; i < orders.length; ++i) {
342:             
343:             _settlePayment( // <= FOUND
344:                 orders[i].items,
345:                 orders[i].orderType,
346:                 orders[i].lender,
347:                 orders[i].renter,
348:                 orders[i].startTimestamp,
349:                 orders[i].endTimestamp
350:             );
351:         }

```


*GitHub* : [341](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L341-L343)

```solidity
475:        for (uint256 i = 0; i < hooks.length; ++i) {
476:             
477:             target = hooks[i].target;
478: 
479:             
480:             if (!STORE.hookOnStart(target)) { // <= FOUND
481:                 revert Errors.Shared_DisabledHook(target);
482:             }
483: 
484:             
485:             itemIndex = hooks[i].itemIndex;
486: 
487:             
488:             offer = offerItems[itemIndex];
489: 
490:             
491:             if (!offer.isRental()) {
492:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
493:             }
494: 
495:             
496:             try
497:                 IHook(target).onStart(
498:                     rentalWallet,
499:                     offer.token,
500:                     offer.identifier,
501:                     offer.amount,
502:                     hooks[i].extraData
503:                 )
504:             {} catch Error(string memory revertReason) {
505:                 
506:                 revert Errors.Shared_HookFailString(revertReason);
507:             } catch Panic(uint256 errorCode) {
508:                 
509:                 string memory stringErrorCode = LibString.toString(errorCode);
510: 
511:                 
512:                 revert Errors.Shared_HookFailString(
513:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
514:                 );
515:             } catch (bytes memory revertData) {
516:                 
517:                 revert Errors.Shared_HookFailBytes(revertData);
518:             }
519:         }

```


*GitHub* : [475](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L475-L480)

```solidity
205:        for (uint256 i = 0; i < hooks.length; ++i) {
206:             
207:             target = hooks[i].target;
208: 
209:             
210:             if (!STORE.hookOnStop(target)) { // <= FOUND
211:                 revert Errors.Shared_DisabledHook(target);
212:             }
213: 
214:             
215:             itemIndex = hooks[i].itemIndex;
216: 
217:             
218:             item = rentalItems[itemIndex];
219: 
220:             
221:             if (!item.isRental()) {
222:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
223:             }
224: 
225:             
226:             try
227:                 IHook(target).onStop(
228:                     rentalWallet,
229:                     item.token,
230:                     item.identifier,
231:                     item.amount,
232:                     hooks[i].extraData
233:                 )
234:             {} catch Error(string memory revertReason) {
235:                 
236:                 revert Errors.Shared_HookFailString(revertReason);
237:             } catch Panic(uint256 errorCode) {
238:                 
239:                 string memory stringErrorCode = LibString.toString(errorCode);
240: 
241:                 
242:                 revert Errors.Shared_HookFailString(
243:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
244:                 );
245:             } catch (bytes memory revertData) {
246:                 
247:                 revert Errors.Shared_HookFailBytes(revertData);
248:             }
249:         }

```


*GitHub* : [205](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L205-L210)

```solidity
276:        for (uint256 i; i < order.items.length; ++i) {
277:             if (order.items[i].isRental()) {
278:                 
279:                 _insert( // <= FOUND
280:                     rentalAssetUpdates,
281:                     order.items[i].toRentalId(order.rentalWallet),
282:                     order.items[i].amount
283:                 );
284:             }
285:         }

```


*GitHub* : [276](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L276-L279)

```solidity
324:        for (uint256 i = 0; i < orders.length; ++i) {
325:             
326:             _validateRentalCanBeStoped( // <= FOUND
327:                 orders[i].orderType,
328:                 orders[i].endTimestamp,
329:                 orders[i].lender
330:             );
331: 
332:             
333:             for (uint256 j = 0; j < orders[i].items.length; ++j) {
334:                 
335:                 if (orders[i].items[j].isRental()) {
336:                     _insert( // <= FOUND
337:                         rentalAssetUpdates,
338:                         orders[i].items[j].toRentalId(orders[i].rentalWallet),
339:                         orders[i].items[j].amount
340:                     );
341:                 }
342:             }
343: 
344:             
345:             orderHashes[i] = _deriveRentalOrderHash(orders[i]); // <= FOUND
346: 
347:             
348:             if (orders[i].hooks.length > 0) {
349:                 _removeHooks(orders[i].hooks, orders[i].items, orders[i].rentalWallet); // <= FOUND
350:             }
351: 
352:             
353:             _reclaimRentedItems(orders[i]); // <= FOUND
354: 
355:             
356:             _emitRentalOrderStopped(orderHashes[i], msg.sender); // <= FOUND
357:         }

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L324-L356)

```solidity
170:        for (uint256 i = 0; i < order.items.length; ++i) {
171:             
172:             itemHashes[i] = _deriveItemHash(order.items[i]); // <= FOUND
173:         }

```


*GitHub* : [170](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L170-L172)

```solidity
225:        for (uint256 i = 0; i < metadata.hooks.length; ++i) {
226:             
227:             hookHashes[i] = _deriveHookHash(metadata.hooks[i]); // <= FOUND
228:         }

```


*GitHub* : [225](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L225-L227)

```solidity
546:        for (uint256 i; i < depLength; ++i) {
547:             
548:             dependents[i].configureDependencies(); // <= FOUND
549:         }

```


*GitHub* : [546](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L546-L548)

```solidity
695:        for (uint256 i = 0; i < executions.length; ++i) {
696:             ReceivedItem memory execution = executions[i];
697: 
698:             
699:             if (execution.isERC20()) {
700:                 _checkExpectedRecipient(execution, address(ESCRW)); // <= FOUND
701:             }
702:             
703:             
704:             else if (execution.isRental()) {
705:                 _checkExpectedRecipient(execution, expectedRentalSafe); // <= FOUND
706:             }
707:             
708:             else {
709:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
710:                     execution.itemType
711:                 );
712:             }
713:         }

```


*GitHub* : [695](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L695-L705)

```solidity
512:        for (uint256 i; i < keycodeLen; ++i) {
513:             
514:             Module module = Module(getModuleForKeycode[allKeycodes[i]]);
515:             
516:             module.changeKernel(newKernel_); // <= FOUND
517:         }

```


*GitHub* : [512](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L512-L516)
### [L-06]<a name="l-06"></a> For loops in public or external functions should be avoided due to high gas costs and possible DOS
In Solidity, for loops can potentially cause Denial of Service (DoS) attacks if not handled carefully. DoS attacks can occur when an attacker intentionally exploits the gas cost of a function, causing it to run out of gas or making it too expensive for other users to call. Below are some scenarios where for loops can lead to DoS attacks: Nested for loops can become exceptionally gas expensive and should be used sparingly

*There are 3 instance(s) of this issue:*

```solidity
71:     function reclaimRentalOrder(RentalOrder calldata rentalOrder) external {
72:         
73:         if (address(this) == original) {
74:             revert Errors.ReclaimerPackage_OnlyDelegateCallAllowed();
75:         }
76: 
77:         
78:         
79:         
80:         if (address(this) != rentalOrder.rentalWallet) {
81:             revert Errors.ReclaimerPackage_OnlyRentalSafeAllowed(
82:                 rentalOrder.rentalWallet
83:             );
84:         }
85: 
86:         
87:         uint256 itemCount = rentalOrder.items.length;
88: 
89:         
90:         for (uint256 i = 0; i < itemCount; ++i) { // <= FOUND
91:             Item memory item = rentalOrder.items[i];
92: 
93:             
94:             if (item.itemType == ItemType.ERC721)
95:                 _transferERC721(item, rentalOrder.lender);
96: 
97:             
98:             if (item.itemType == ItemType.ERC1155)
99:                 _transferERC1155(item, rentalOrder.lender);
100:         }
101:     }

```


*GitHub* : [90](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L90-L90)

```solidity
265:     function stopRent(RentalOrder calldata order) external {
266:         
267:         _validateRentalCanBeStoped(order.orderType, order.endTimestamp, order.lender);
268: 
269:         
270:         
271:         
272:         bytes memory rentalAssetUpdates = new bytes(0);
273: 
274:         
275:         
276:         for (uint256 i; i < order.items.length; ++i) { // <= FOUND
277:             if (order.items[i].isRental()) {
278:                 
279:                 _insert(
280:                     rentalAssetUpdates,
281:                     order.items[i].toRentalId(order.rentalWallet),
282:                     order.items[i].amount
283:                 );
284:             }
285:         }
286: 
287:         
288:         if (order.hooks.length > 0) {
289:             _removeHooks(order.hooks, order.items, order.rentalWallet);
290:         }
291: 
292:         
293:         _reclaimRentedItems(order);
294: 
295:         
296:         ESCRW.settlePayment(order);
297: 
298:         
299:         STORE.removeRentals(
300:             _deriveRentalOrderHash(order),
301:             _convertToStatic(rentalAssetUpdates)
302:         );
303: 
304:         
305:         _emitRentalOrderStopped(order.seaportOrderHash, msg.sender);
306:     }

```


*GitHub* : [276](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L276-L276)

```solidity
313:     function stopRentBatch(RentalOrder[] calldata orders) external {
314:         
315:         bytes32[] memory orderHashes = new bytes32[](orders.length);
316: 
317:         
318:         
319:         
320:         bytes memory rentalAssetUpdates = new bytes(0);
321: 
322:         
323:         
324:         for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND
325:             
326:             _validateRentalCanBeStoped(
327:                 orders[i].orderType,
328:                 orders[i].endTimestamp,
329:                 orders[i].lender
330:             );
331: 
332:             
333:             for (uint256 j = 0; j < orders[i].items.length; ++j) { // <= FOUND
334:                 
335:                 if (orders[i].items[j].isRental()) {
336:                     _insert(
337:                         rentalAssetUpdates,
338:                         orders[i].items[j].toRentalId(orders[i].rentalWallet),
339:                         orders[i].items[j].amount
340:                     );
341:                 }
342:             }
343: 
344:             
345:             orderHashes[i] = _deriveRentalOrderHash(orders[i]);
346: 
347:             
348:             if (orders[i].hooks.length > 0) {
349:                 _removeHooks(orders[i].hooks, orders[i].items, orders[i].rentalWallet);
350:             }
351: 
352:             
353:             _reclaimRentedItems(orders[i]);
354: 
355:             
356:             _emitRentalOrderStopped(orderHashes[i], msg.sender);
357:         }
358: 
359:         
360:         ESCRW.settlePaymentBatch(orders);
361: 
362:         
363:         STORE.removeRentalsBatch(orderHashes, _convertToStatic(rentalAssetUpdates));
364:     }

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L324-L333)
### [L-07]<a name="l-07"></a> Missing zero address check in constructor
In Solidity, constructors often take address parameters to initialize important components of a contract, such as owner or linked contracts. However, without a check, there's a risk that an address parameter could be mistakenly set to the zero address (0x0). This could occur due to a mistake or oversight during contract deployment. A zero address in a crucial role can cause serious issues, as it cannot perform actions like a normal address, and any funds sent to it are irretrievable. Therefore, it's crucial to include a zero address check in constructors to prevent such potential problems. If a zero address is detected, the constructor should revert the transaction.

*There are 1 instance(s) of this issue:*

```solidity
242:     constructor(address _executor, address _admin) { // <= FOUND
243:         executor = _executor;
244:         admin = _admin;
245:     }

```


*GitHub* : [242](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L242-L242)
### [L-08]<a name="l-08"></a> Using zero as a parameter
Taking 0 as a valid argument in Solidity without checks can lead to severe security issues. A historical example is the infamous 0x0 address bug where numerous tokens were lost. This happens because '0' can be interpreted as an uninitialized address, leading to transfers to the '0x0' address, effectively burning tokens. Moreover, 0 as a denominator in division operations would cause a runtime exception. It's also often indicative of a logical error in the caller's code. It's important to always validate input and handle edge cases like 0 appropriately. Use `require()` statements to enforce conditions and provide clear error messages to facilitate debugging and safer code.

*There are 1 instance(s) of this issue:*

```solidity
411:     function _convertToItems(
412:         SpentItem[] memory offers,
413:         ReceivedItem[] memory considerations,
414:         OrderType orderType
415:     ) internal pure returns (Item[] memory items) {
416:         
417:         items = new Item[](offers.length + considerations.length);
418: 
419:         
420:         if (orderType.isBaseOrder()) {
421:             
422:             _processBaseOrderOffer(items, offers, 0);
423: 
424:             
425:             _processBaseOrderConsideration(items, considerations, offers.length);
426:         }
427:         
428:         else if (orderType.isPayOrder()) {
429:             
430:             _processPayOrderOffer(items, offers, 0);
431: 
432:             
433:             if (considerations.length > 0) {
434:                 revert Errors.CreatePolicy_ConsiderationCountNonZero(
435:                     considerations.length
436:                 );
437:             }
438:         }
439:         
440:         else if (orderType.isPayeeOrder()) {
441:             
442:             if (offers.length > 0) {
443:                 revert Errors.CreatePolicy_OfferCountNonZero(offers.length);
444:             }
445: 
446:             
447:             _processPayeeOrderConsideration(considerations);
448:         }
449:         
450:         else {
451:             revert Errors.Shared_OrderTypeNotSupported(uint8(orderType));
452:         }
453:     }

```


*GitHub* : [411](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L411-L411)
### [L-09]<a name="l-09"></a> Critical functions should be a two step procedure
Critical functions in Solidity contracts should follow a two-step procedure to enhance security, minimize human error, and ensure proper access control. By dividing sensitive operations into distinct phases, such as initiation and confirmation, developers can introduce a safeguard against unintended actions or unauthorized access.

*There are 3 instance(s) of this issue:*

```solidity
173:     function setFee(uint256 feeNumerator) external onlyRole("ADMIN_ADMIN")  // <= FOUND

```


*GitHub* : [173](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L173-L173)

```solidity
362:     function updateHookPath(address to, address hook) external onlyRole("GUARD_ADMIN")  // <= FOUND

```


*GitHub* : [362](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L362-L362)

```solidity
373:     function updateHookStatus( // <= FOUND
374:         address hook,
375:         uint8 bitmap
376:     ) external onlyRole("GUARD_ADMIN") 

```


*GitHub* : [373](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L373-L373)
### [L-10]<a name="l-10"></a> Arrays can grow in size without a way to shrink them
It's a good practice to maintain control over the size of array state variables in Solidity, especially if they are dynamically updated. If a contract includes a mechanism to push items into an array, it should ideally also provide a mechanism to remove items. This is because Solidity arrays don't automatically shrink when items are deleted - their length needs to be manually adjusted.

Ignoring this can lead to bloated and inefficient contracts. For instance, iterating over a large array can cause your contract to hit the block gas limit. Additionally, if entries are only marked for deletion but never actually removed, you may end up dealing with stale or irrelevant data, which can cause logical errors.

Therefore, implementing a method to 'pop' items from arrays helps manage contract's state, improve efficiency and prevent potential issues related to gas limits or stale data. Always ensure to handle potential underflow conditions when popping elements from the array. In this particular case, as 'allKeyCodes' is iterated upon, this could brick the functionality of '_migrateKernel function.

*There are 1 instance(s) of this issue:*

```solidity
212: Keycode[] public allKeycodes; // <= FOUND

```


*GitHub* : [212](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L212-L212)
### [L-11]<a name="l-11"></a> Revert on Transfer to the Zero Address
Many ERC-20 and ERC-721 token contracts implement a safeguard that reverts transactions which attempt to transfer tokens to the zero address. This is because such transfers are often the result of programming errors. The OpenZeppelin library, a popular choice for implementing these standards, includes this safeguard. For token contract developers who want to avoid unintentional transfers to the zero address, it's good practice to include a condition that reverts the transaction if the recipient's address is the zero address.

*There are 1 instance(s) of this issue:*

```solidity
42:     function _transferERC1155(Item memory item, address recipient) private {
43:         IERC1155(item.token).safeTransferFrom( // <= FOUND
44:             address(this),
45:             recipient,
46:             item.identifier,
47:             item.amount,
48:             ""
49:         );
50:     }

```


*GitHub* : [42](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L42-L43)
### [L-12]<a name="l-12"></a> Sweeping may break accounting if tokens with multiple addresses are used
In the realm of token contracts, there have been historical instances where a token inadvertently had two controlling addresses, such that transfers made via one would affect the balance of the other. This raises potential security concerns and anomalies in the balance of accounts. To guard against such potential scenarios in functions that "sweep" or transfer tokens, it is prudent to validate that the balance of any non-sweepable or exempt tokens remains unaffected post the sweep operation. This measure ensures integrity of the account balances and prevents unintended changes due to potential hidden correlations between different token addresses.

*There are 1 instance(s) of this issue:*

```solidity
107:     function _recoverSignerFromPayload( // <= FOUND
108:         bytes32 payloadHash,
109:         bytes memory signature
110:     ) internal view returns (address) {
111:         
112:         bytes32 digest = _DOMAIN_SEPARATOR.toTypedDataHash(payloadHash);
113: 
114:         
115:         return digest.recover(signature); // <= FOUND
116:     }

```


*GitHub* : [107](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L107-L115)
### [L-13]<a name="l-13"></a> Missing zero address check in initializer
Initializer functions in contracts often set important parameters or addresses. Failing to check for the zero address (0x0000000000000000000000000000000000000000) in initializers can lead to unintended behavior, as this address typically signifies an unset or default value. Transfers to or interactions with the zero address can result in permanent loss of assets or broken functionality. It's crucial to add checks using `require(targetAddress != address(0), "Address cannot be zero")` in initializers to prevent accidentally setting important state variables or parameters to this address, ensuring the system's integrity and user asset safety.

*There are 1 instance(s) of this issue:*

```solidity
122:     function initializeRentalSafe(address _stopPolicy, address _guardPolicy) external {
123:         
124:         ISafe(address(this)).enableModule(_stopPolicy);
125: 
126:         
127:         ISafe(address(this)).setGuard(_guardPolicy);
128:     }

```


*GitHub* : [122](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L122-L122)
### [L-14]<a name="l-14"></a> Critical functions should have a timelock
Critical functions, especially those affecting protocol parameters or user funds, are potential points of failure or exploitation. To mitigate risks, incorporating a timelock on such functions can be beneficial. A timelock requires a waiting period between the time an action is initiated and when it's executed, giving stakeholders time to react, potentially vetoing malicious or erroneous changes. To implement, integrate a smart contract like OpenZeppelin's `TimelockController` or build a custom mechanism. This ensures governance decisions or administrative changes are transparent and allows for community or multi-signature interventions, enhancing protocol security and trustworthiness.

*There are 1 instance(s) of this issue:*

```solidity
173:     function setFee(uint256 feeNumerator) external onlyRole("ADMIN_ADMIN")  // <= FOUND

```


*GitHub* : [173](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L173-L173)
### [L-15]<a name="l-15"></a> Unbounded loop may run out of gas
Unbounded loops in smart contracts pose a risk because they iterate over an unknown number of elements, potentially consuming all available gas for a transaction. This can result in unintended transaction failures. Gas consumption increases linearly with the number of iterations, and if it surpasses the gas limit, the transaction reverts, wasting the gas spent. To mitigate this, developers should either set a maximum limit on loop iterations.

*There are 17 instance(s) of this issue:*

```solidity
215:     function _settlePayment(
216:         Item[] calldata items,
217:         OrderType orderType,
218:         address lender,
219:         address renter,
220:         uint256 start,
221:         uint256 end
222:     ) internal {
223:         
224:         uint256 elapsedTime = block.timestamp - start;
225:         uint256 totalTime = end - start;
226: 
227:         
228:         bool isRentalOver = elapsedTime >= totalTime;
229: 
230:         
231:         for (uint256 i = 0; i < items.length; ++i) {
232:             
233:             Item memory item = items[i];
234: 
235:             
236:             if (item.isERC20()) {
237:                 
238:                 
239:                 uint256 paymentAmount = item.amount;
240: 
241:                 
242:                 if (fee != 0) {
243:                     
244:                     uint256 paymentFee = _calculateFee(paymentAmount);
245: 
246:                     
247:                     paymentAmount -= paymentFee;
248:                 }
249: 
250:                 
251:                 
252:                 _decreaseDeposit(item.token, item.amount);
253: 
254:                 
255:                 if (orderType.isPayOrder() && !isRentalOver) {
256:                     
257:                     _settlePaymentProRata(
258:                         item.token,
259:                         paymentAmount,
260:                         lender,
261:                         renter,
262:                         elapsedTime,
263:                         totalTime
264:                     );
265:                 }
266:                 
267:                 else if (
268:                     (orderType.isPayOrder() && isRentalOver) || orderType.isBaseOrder()
269:                 ) {
270:                     
271:                     _settlePaymentInFull(
272:                         item.token,
273:                         paymentAmount,
274:                         item.settleTo,
275:                         lender,
276:                         renter
277:                     );
278:                 } else {
279:                     revert Errors.Shared_OrderTypeNotSupported(uint8(orderType));
280:                 }
281:             }
282:         }
283:     }

```


*GitHub* : [215](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L215-L215)

```solidity
337:     function settlePaymentBatch(
338:         RentalOrder[] calldata orders
339:     ) external onlyByProxy permissioned {
340:         
341:         for (uint256 i = 0; i < orders.length; ++i) {
342:             
343:             _settlePayment(
344:                 orders[i].items,
345:                 orders[i].orderType,
346:                 orders[i].lender,
347:                 orders[i].renter,
348:                 orders[i].startTimestamp,
349:                 orders[i].endTimestamp
350:             );
351:         }
352:     }

```


*GitHub* : [337](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L337-L337)

```solidity
189:     function addRentals(
190:         bytes32 orderHash,
191:         RentalAssetUpdate[] memory rentalAssetUpdates
192:     ) external onlyByProxy permissioned {
193:         
194:         orders[orderHash] = true;
195: 
196:         
197:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {
198:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
199: 
200:             
201:             rentedAssets[asset.rentalId] += asset.amount;
202:         }
203:     }

```


*GitHub* : [189](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L189-L189)

```solidity
216:     function removeRentals(
217:         bytes32 orderHash,
218:         RentalAssetUpdate[] calldata rentalAssetUpdates
219:     ) external onlyByProxy permissioned {
220:         
221:         if (!orders[orderHash]) {
222:             revert Errors.StorageModule_OrderDoesNotExist(orderHash);
223:         } else {
224:             
225:             delete orders[orderHash];
226:         }
227: 
228:         
229:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {
230:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
231: 
232:             
233:             rentedAssets[asset.rentalId] -= asset.amount;
234:         }
235:     }

```


*GitHub* : [216](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L216-L216)

```solidity
244:     function removeRentalsBatch(
245:         bytes32[] calldata orderHashes,
246:         RentalAssetUpdate[] calldata rentalAssetUpdates
247:     ) external onlyByProxy permissioned {
248:         
249:         for (uint256 i = 0; i < orderHashes.length; ++i) {
250:             
251:             if (!orders[orderHashes[i]]) {
252:                 revert Errors.StorageModule_OrderDoesNotExist(orderHashes[i]);
253:             } else {
254:                 
255:                 delete orders[orderHashes[i]];
256:             }
257:         }
258: 
259:         
260:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {
261:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
262: 
263:             
264:             rentedAssets[asset.rentalId] -= asset.amount;
265:         }
266:     }

```


*GitHub* : [244](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L244-L244)

```solidity
162:     function _deriveRentalOrderHash(
163:         RentalOrder memory order
164:     ) internal view returns (bytes32) {
165:         
166:         bytes32[] memory itemHashes = new bytes32[](order.items.length);
167:         bytes32[] memory hookHashes = new bytes32[](order.hooks.length);
168: 
169:         
170:         for (uint256 i = 0; i < order.items.length; ++i) {
171:             
172:             itemHashes[i] = _deriveItemHash(order.items[i]);
173:         }
174: 
175:         
176:         for (uint256 i = 0; i < order.hooks.length; ++i) {
177:             
178:             hookHashes[i] = _deriveHookHash(order.hooks[i]);
179:         }
180: 
181:         return
182:             keccak256(
183:                 abi.encode(
184:                     _RENTAL_ORDER_TYPEHASH,
185:                     order.seaportOrderHash,
186:                     keccak256(abi.encodePacked(itemHashes)),
187:                     keccak256(abi.encodePacked(hookHashes)),
188:                     order.orderType,
189:                     order.lender,
190:                     order.renter,
191:                     order.startTimestamp,
192:                     order.endTimestamp
193:                 )
194:             );
195:     }

```


*GitHub* : [162](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L162-L162)

```solidity
218:     function _deriveOrderMetadataHash(
219:         OrderMetadata memory metadata
220:     ) internal view returns (bytes32) {
221:         
222:         bytes32[] memory hookHashes = new bytes32[](metadata.hooks.length);
223: 
224:         
225:         for (uint256 i = 0; i < metadata.hooks.length; ++i) {
226:             
227:             hookHashes[i] = _deriveHookHash(metadata.hooks[i]);
228:         }
229: 
230:         
231:         return
232:             keccak256(
233:                 abi.encode(
234:                     _ORDER_METADATA_TYPEHASH,
235:                     metadata.rentDuration,
236:                     keccak256(abi.encodePacked(hookHashes))
237:                 )
238:             );
239:     }

```


*GitHub* : [218](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L218-L218)

```solidity
195:     function _processBaseOrderOffer(
196:         Item[] memory rentalItems,
197:         SpentItem[] memory offers,
198:         uint256 startIndex
199:     ) internal pure {
200:         
201:         if (offers.length == 0) {
202:             revert Errors.CreatePolicy_OfferCountZero();
203:         }
204: 
205:         
206:         ItemType itemType;
207: 
208:         
209:         for (uint256 i; i < offers.length; ++i) {
210:             
211:             SpentItem memory offer = offers[i];
212: 
213:             
214:             if (offer.isERC721()) {
215:                 itemType = ItemType.ERC721;
216:             }
217:             
218:             else if (offer.isERC1155()) {
219:                 itemType = ItemType.ERC1155;
220:             }
221:             
222:             else {
223:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(offer.itemType);
224:             }
225: 
226:             
227:             
228:             rentalItems[i + startIndex] = Item({
229:                 itemType: itemType,
230:                 settleTo: SettleTo.LENDER,
231:                 token: offer.token,
232:                 amount: offer.amount,
233:                 identifier: offer.identifier
234:             });
235:         }
236:     }

```


*GitHub* : [195](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L195-L195)

```solidity
247:     function _processPayOrderOffer(
248:         Item[] memory rentalItems,
249:         SpentItem[] memory offers,
250:         uint256 startIndex
251:     ) internal pure {
252:         
253:         uint256 totalRentals;
254:         uint256 totalPayments;
255: 
256:         
257:         ItemType itemType;
258:         SettleTo settleTo;
259: 
260:         
261:         for (uint256 i; i < offers.length; ++i) {
262:             
263:             SpentItem memory offer = offers[i];
264: 
265:             
266:             if (offer.isERC721()) {
267:                 
268:                 
269:                 itemType = ItemType.ERC721;
270:                 settleTo = SettleTo.LENDER;
271: 
272:                 
273:                 totalRentals++;
274:             }
275:             
276:             else if (offer.isERC1155()) {
277:                 
278:                 
279:                 itemType = ItemType.ERC1155;
280:                 settleTo = SettleTo.LENDER;
281: 
282:                 
283:                 totalRentals++;
284:             }
285:             
286:             else if (offer.isERC20()) {
287:                 
288:                 
289:                 itemType = ItemType.ERC20;
290:                 settleTo = SettleTo.RENTER;
291: 
292:                 
293:                 totalPayments++;
294:             }
295:             
296:             else {
297:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(offer.itemType);
298:             }
299: 
300:             
301:             rentalItems[i + startIndex] = Item({
302:                 itemType: itemType,
303:                 settleTo: settleTo,
304:                 token: offer.token,
305:                 amount: offer.amount,
306:                 identifier: offer.identifier
307:             });
308:         }
309: 
310:         
311:         if (totalRentals == 0 || totalPayments == 0) {
312:             revert Errors.CreatePolicy_ItemCountZero(totalRentals, totalPayments);
313:         }
314:     }

```


*GitHub* : [247](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L247-L247)

```solidity
326:     function _processBaseOrderConsideration(
327:         Item[] memory rentalItems,
328:         ReceivedItem[] memory considerations,
329:         uint256 startIndex
330:     ) internal pure {
331:         
332:         if (considerations.length == 0) {
333:             revert Errors.CreatePolicy_ConsiderationCountZero();
334:         }
335: 
336:         
337:         for (uint256 i; i < considerations.length; ++i) {
338:             
339:             ReceivedItem memory consideration = considerations[i];
340: 
341:             
342:             if (!consideration.isERC20()) {
343:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
344:                     consideration.itemType
345:                 );
346:             }
347: 
348:             
349:             
350:             rentalItems[i + startIndex] = Item({
351:                 itemType: ItemType.ERC20,
352:                 settleTo: SettleTo.LENDER,
353:                 token: consideration.token,
354:                 amount: consideration.amount,
355:                 identifier: consideration.identifier
356:             });
357:         }
358:     }

```


*GitHub* : [326](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L326-L326)

```solidity
367:     function _processPayeeOrderConsideration(
368:         ReceivedItem[] memory considerations
369:     ) internal pure {
370:         
371:         uint256 totalRentals;
372:         uint256 totalPayments;
373: 
374:         
375:         for (uint256 i; i < considerations.length; ++i) {
376:             
377:             ReceivedItem memory consideration = considerations[i];
378: 
379:             
380:             if (consideration.isERC20()) {
381:                 totalPayments++;
382:             }
383:             
384:             else if (consideration.isRental()) {
385:                 totalRentals++;
386:             }
387:             
388:             else {
389:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
390:                     consideration.itemType
391:                 );
392:             }
393:         }
394: 
395:         
396:         if (totalRentals == 0 || totalPayments == 0) {
397:             revert Errors.CreatePolicy_ItemCountZero(totalRentals, totalPayments);
398:         }
399:     }

```


*GitHub* : [367](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L367-L367)

```solidity
464:     function _addHooks(
465:         Hook[] memory hooks,
466:         SpentItem[] memory offerItems,
467:         address rentalWallet
468:     ) internal {
469:         
470:         address target;
471:         uint256 itemIndex;
472:         SpentItem memory offer;
473: 
474:         
475:         for (uint256 i = 0; i < hooks.length; ++i) {
476:             
477:             target = hooks[i].target;
478: 
479:             
480:             if (!STORE.hookOnStart(target)) {
481:                 revert Errors.Shared_DisabledHook(target);
482:             }
483: 
484:             
485:             itemIndex = hooks[i].itemIndex;
486: 
487:             
488:             offer = offerItems[itemIndex];
489: 
490:             
491:             if (!offer.isRental()) {
492:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
493:             }
494: 
495:             
496:             try
497:                 IHook(target).onStart(
498:                     rentalWallet,
499:                     offer.token,
500:                     offer.identifier,
501:                     offer.amount,
502:                     hooks[i].extraData
503:                 )
504:             {} catch Error(string memory revertReason) {
505:                 
506:                 revert Errors.Shared_HookFailString(revertReason);
507:             } catch Panic(uint256 errorCode) {
508:                 
509:                 string memory stringErrorCode = LibString.toString(errorCode);
510: 
511:                 
512:                 revert Errors.Shared_HookFailString(
513:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
514:                 );
515:             } catch (bytes memory revertData) {
516:                 
517:                 revert Errors.Shared_HookFailBytes(revertData);
518:             }
519:         }
520:     }

```


*GitHub* : [464](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L464-L464)

```solidity
530:     function _rentFromZone(
531:         RentPayload memory payload,
532:         SeaportPayload memory seaportPayload
533:     ) internal {
534:         
535:         _isValidOrderMetadata(payload.metadata, seaportPayload.zoneHash);
536: 
537:         
538:         _isValidSafeOwner(seaportPayload.fulfiller, payload.fulfillment.recipient);
539: 
540:         
541:         _executionInvariantChecks(
542:             seaportPayload.totalExecutions,
543:             payload.fulfillment.recipient
544:         );
545: 
546:         
547:         
548:         Item[] memory items = _convertToItems(
549:             seaportPayload.offer,
550:             seaportPayload.consideration,
551:             payload.metadata.orderType
552:         );
553: 
554:         
555:         
556:         if (
557:             payload.metadata.orderType.isBaseOrder() ||
558:             payload.metadata.orderType.isPayOrder()
559:         ) {
560:             
561:             
562:             
563:             bytes memory rentalAssetUpdates = new bytes(0);
564: 
565:             
566:             
567:             for (uint256 i; i < items.length; ++i) {
568:                 if (items[i].isRental()) {
569:                     
570:                     _insert(
571:                         rentalAssetUpdates,
572:                         items[i].toRentalId(payload.fulfillment.recipient),
573:                         items[i].amount
574:                     );
575:                 }
576:             }
577: 
578:             
579:             RentalOrder memory order = RentalOrder({
580:                 seaportOrderHash: seaportPayload.orderHash,
581:                 items: items,
582:                 hooks: payload.metadata.hooks,
583:                 orderType: payload.metadata.orderType,
584:                 lender: seaportPayload.offerer,
585:                 renter: payload.intendedFulfiller,
586:                 rentalWallet: payload.fulfillment.recipient,
587:                 startTimestamp: block.timestamp,
588:                 endTimestamp: block.timestamp + payload.metadata.rentDuration
589:             });
590: 
591:             
592:             bytes32 orderHash = _deriveRentalOrderHash(order);
593: 
594:             
595:             STORE.addRentals(orderHash, _convertToStatic(rentalAssetUpdates));
596: 
597:             
598:             
599:             for (uint256 i = 0; i < items.length; ++i) {
600:                 if (items[i].isERC20()) {
601:                     ESCRW.increaseDeposit(items[i].token, items[i].amount);
602:                 }
603:             }
604: 
605:             
606:             if (payload.metadata.hooks.length > 0) {
607:                 _addHooks(
608:                     payload.metadata.hooks,
609:                     seaportPayload.offer,
610:                     payload.fulfillment.recipient
611:                 );
612:             }
613: 
614:             
615:             _emitRentalOrderStarted(order, orderHash, payload.metadata.emittedExtraData);
616:         }
617:     }

```


*GitHub* : [530](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L530-L530)

```solidity
691:     function _executionInvariantChecks(
692:         ReceivedItem[] memory executions,
693:         address expectedRentalSafe
694:     ) internal view {
695:         for (uint256 i = 0; i < executions.length; ++i) { // <= FOUND
696:             ReceivedItem memory execution = executions[i];
697: 
698:             
699:             if (execution.isERC20()) {
700:                 _checkExpectedRecipient(execution, address(ESCRW));
701:             }
702:             
703:             
704:             else if (execution.isRental()) {
705:                 _checkExpectedRecipient(execution, expectedRentalSafe);
706:             }
707:             
708:             else {
709:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
710:                     execution.itemType
711:                 );
712:             }
713:         }
714:     }

```


*GitHub* : [691](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L691-L695)

```solidity
194:     function _removeHooks(
195:         Hook[] calldata hooks,
196:         Item[] calldata rentalItems,
197:         address rentalWallet
198:     ) internal {
199:         
200:         address target;
201:         uint256 itemIndex;
202:         Item memory item;
203: 
204:         
205:         for (uint256 i = 0; i < hooks.length; ++i) {
206:             
207:             target = hooks[i].target;
208: 
209:             
210:             if (!STORE.hookOnStop(target)) {
211:                 revert Errors.Shared_DisabledHook(target);
212:             }
213: 
214:             
215:             itemIndex = hooks[i].itemIndex;
216: 
217:             
218:             item = rentalItems[itemIndex];
219: 
220:             
221:             if (!item.isRental()) {
222:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
223:             }
224: 
225:             
226:             try
227:                 IHook(target).onStop(
228:                     rentalWallet,
229:                     item.token,
230:                     item.identifier,
231:                     item.amount,
232:                     hooks[i].extraData
233:                 )
234:             {} catch Error(string memory revertReason) {
235:                 
236:                 revert Errors.Shared_HookFailString(revertReason);
237:             } catch Panic(uint256 errorCode) {
238:                 
239:                 string memory stringErrorCode = LibString.toString(errorCode);
240: 
241:                 
242:                 revert Errors.Shared_HookFailString(
243:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
244:                 );
245:             } catch (bytes memory revertData) {
246:                 
247:                 revert Errors.Shared_HookFailBytes(revertData);
248:             }
249:         }
250:     }

```


*GitHub* : [194](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L194-L194)

```solidity
265:     function stopRent(RentalOrder calldata order) external { // <= FOUND
266:         
267:         _validateRentalCanBeStoped(order.orderType, order.endTimestamp, order.lender);
268: 
269:         
270:         
271:         
272:         bytes memory rentalAssetUpdates = new bytes(0);
273: 
274:         
275:         
276:         for (uint256 i; i < order.items.length; ++i) {
277:             if (order.items[i].isRental()) {
278:                 
279:                 _insert(
280:                     rentalAssetUpdates,
281:                     order.items[i].toRentalId(order.rentalWallet),
282:                     order.items[i].amount
283:                 );
284:             }
285:         }
286: 
287:         
288:         if (order.hooks.length > 0) {
289:             _removeHooks(order.hooks, order.items, order.rentalWallet);
290:         }
291: 
292:         
293:         _reclaimRentedItems(order);
294: 
295:         
296:         ESCRW.settlePayment(order);
297: 
298:         
299:         STORE.removeRentals(
300:             _deriveRentalOrderHash(order),
301:             _convertToStatic(rentalAssetUpdates)
302:         );
303: 
304:         
305:         _emitRentalOrderStopped(order.seaportOrderHash, msg.sender);
306:     }

```


*GitHub* : [265](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L265-L265)

```solidity
313:     function stopRentBatch(RentalOrder[] calldata orders) external { // <= FOUND
314:         
315:         bytes32[] memory orderHashes = new bytes32[](orders.length);
316: 
317:         
318:         
319:         
320:         bytes memory rentalAssetUpdates = new bytes(0);
321: 
322:         
323:         
324:         for (uint256 i = 0; i < orders.length; ++i) {
325:             
326:             _validateRentalCanBeStoped(
327:                 orders[i].orderType,
328:                 orders[i].endTimestamp,
329:                 orders[i].lender
330:             );
331: 
332:             
333:             for (uint256 j = 0; j < orders[i].items.length; ++j) {
334:                 
335:                 if (orders[i].items[j].isRental()) {
336:                     _insert(
337:                         rentalAssetUpdates,
338:                         orders[i].items[j].toRentalId(orders[i].rentalWallet),
339:                         orders[i].items[j].amount
340:                     );
341:                 }
342:             }
343: 
344:             
345:             orderHashes[i] = _deriveRentalOrderHash(orders[i]);
346: 
347:             
348:             if (orders[i].hooks.length > 0) {
349:                 _removeHooks(orders[i].hooks, orders[i].items, orders[i].rentalWallet);
350:             }
351: 
352:             
353:             _reclaimRentedItems(orders[i]);
354: 
355:             
356:             _emitRentalOrderStopped(orderHashes[i], msg.sender);
357:         }
358: 
359:         
360:         ESCRW.settlePaymentBatch(orders);
361: 
362:         

```


*GitHub* : [313](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L313-L313)
### [L-16]<a name="l-16"></a> Mapping arrays can grow in size without a way to shrink them
It's a good practice to maintain control over the size of array mappings in Solidity, especially if they are dynamically updated. If a contract includes a mechanism to push items into an array, it should ideally also provide a mechanism to remove items. This is because Solidity arrays don't automatically shrink when items are deleted - their length needs to be manually adjusted.

Ignoring this can lead to bloated and inefficient contracts. For instance, iterating over a large array can cause your contract to hit the block gas limit. Additionally, if entries are only marked for deletion but never actually removed, you may end up dealing with stale or irrelevant data, which can cause logical errors.

Therefore, implementing a method to 'pop' items from mapping arrays helps manage contract's state, improve efficiency and prevent potential issues related to gas limits or stale data. Always ensure to handle potential underflow conditions when popping elements from the mapping array.

*There are 1 instance(s) of this issue:*

```solidity
217:     mapping(Keycode => Policy[]) public moduleDependents; // <= FOUND

```


*GitHub* : [217](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L217-L217)
### [L-17]<a name="l-17"></a> Consider implementing two-step procedure for updating protocol addresses
Implementing a two-step procedure for updating protocol addresses adds an extra layer of security. In such a system, the first step initiates the change, and the second step, after a predefined delay, confirms and finalizes it. This delay allows stakeholders or monitoring tools to observe and react to unintended or malicious changes. If an unauthorized change is detected, corrective actions can be taken before the change is finalized. To achieve this, introduce a "proposed address" state variable and a "delay period". Upon an update request, set the "proposed address". After the delay, if not contested, the main protocol address can be updated.

*There are 1 instance(s) of this issue:*

```solidity
362:     function updateHookPath(address to, address hook) external onlyRole("GUARD_ADMIN") { // <= FOUND
363:         STORE.updateHookPath(to, hook);
364:     }

```


*GitHub* : [362](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L362-L362)
### [L-18]<a name="l-18"></a> Unbounded state array which is iterated upon
Reason: In Solidity, iteration over large arrays can lead to excessive gas consumption. In the worst case scenario, if the array size exceeds the block gas limit, it could make the operation unfeasible. This is a common problem for operations like token distribution, where one might iterate over an array of holders.

Resolution: To prevent gas problems, limit the size of arrays that will be iterated over. Implement an alternative data structure, such as a linked list, which allows for partial iteration. Another solution could be paginated processing, where elements are processed in smaller batches over multiple transactions. Lastly, the use of 'state array' with a separate index-tracking array can also help manage large datasets.

*There are 2 instance(s) of this issue:*

```solidity
418:     function _activatePolicy(Policy policy_) internal { // <= FOUND
419:         
420:         if (policy_.isActive())
421:             revert Errors.Kernel_PolicyAlreadyApproved(address(policy_));
422: 
423:         
424:         Permissions[] memory requests = policy_.requestPermissions();
425:         _setPolicyPermissions(policy_, requests, true);
426: 
427:         
428:         activePolicies.push(policy_);
429: 
430:         
431:         getPolicyIndex[policy_] = activePolicies.length - 1;
432: 
433:         
434:         Keycode[] memory dependencies = policy_.configureDependencies();
435:         uint256 depLength = dependencies.length;
436: 
437:         
438:         for (uint256 i; i < depLength; ++i) {
439:             Keycode keycode = dependencies[i];
440: 
441:             
442:             moduleDependents[keycode].push(policy_);
443: 
444:             
445:             getDependentIndex[keycode][policy_] = moduleDependents[keycode].length - 1;
446:         }
447: 
448:         
449:         policy_.setActiveStatus(true);
450:     }

```


*GitHub* : [418](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L418-L418)

```solidity
508:     function _migrateKernel(Kernel newKernel_) internal { // <= FOUND
509:         uint256 keycodeLen = allKeycodes.length;
510: 
511:         
512:         for (uint256 i; i < keycodeLen; ++i) {
513:             
514:             Module module = Module(getModuleForKeycode[allKeycodes[i]]);
515:             
516:             module.changeKernel(newKernel_);
517:         }
518: 
519:         
520:         uint256 policiesLen = activePolicies.length;
521:         for (uint256 j; j < policiesLen; ++j) {
522:             
523:             Policy policy = activePolicies[j];
524: 
525:             
526:             policy.setActiveStatus(false);
527: 
528:             
529:             policy.changeKernel(newKernel_);
530:         }
531:     }

```


*GitHub* : [508](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L508-L508)
### [L-19]<a name="l-19"></a> External calls in modifiers should be avoided
External calls within modifiers can introduce unintended reentrancy risks and obscure the flow of a contract's logic. Modifiers are designed to perform checks before executing function logic, and using external calls can make the flow unpredictable due to the potential for state changes or reentrancy by the called contract. Such ambiguity makes code harder to audit and understand. To ensure clarity and security, avoid external calls in modifiers. Instead, place them in the function body, where their execution order and effects are more explicit. This practice enhances contract readability, aids auditors, and minimizes unexpected behaviors.

*There are 2 instance(s) of this issue:*

```solidity
77:     modifier permissioned() { // <= FOUND
78:         if (!kernel.modulePermissions(KEYCODE(), Policy(msg.sender), msg.sig)) {
79:             revert Errors.Module_PolicyNotAuthorized(msg.sender); // <= FOUND
80:         }
81:         _;
82:     }

```


*GitHub* : [77](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L77-L79)

```solidity
130:     modifier onlyRole(bytes32 role_) { // <= FOUND
131:         Role role = toRole(role_);
132:         if (!kernel.hasRole(msg.sender, role)) {
133:             revert Errors.Policy_OnlyRole(role); // <= FOUND
134:         }
135:         _;
136:     }

```


*GitHub* : [130](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L130-L133)
### [L-20]<a name="l-20"></a> Prefer skip over revert model in iteration
It is preferable to skip operations on an array index when a condition is not met rather than reverting the whole transaction as reverting can introduce the possiblity of malicous actors purposefully introducing array objects which fail conditional checks within for/while loops so group operations fail. As such it is recommended to simply skip such array indices over reverting unless there is a valid security or logic reason behind not doing so.

*There are 3 instance(s) of this issue:*

```solidity
249:        for (uint256 i = 0; i < orderHashes.length; ++i) { // <= FOUND
250:             
251:             if (!orders[orderHashes[i]]) {
252:                 revert Errors.StorageModule_OrderDoesNotExist(orderHashes[i]); // <= FOUND
253:             } else {
254:                 
255:                 delete orders[orderHashes[i]];
256:             }
257:         }

```


*GitHub* : [249](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L249-L252)

```solidity
475:        for (uint256 i = 0; i < hooks.length; ++i) { // <= FOUND
476:             
477:             target = hooks[i].target;
478: 
479:             
480:             if (!STORE.hookOnStart(target)) {
481:                 revert Errors.Shared_DisabledHook(target);
482:             }
483: 
484:             
485:             itemIndex = hooks[i].itemIndex;
486: 
487:             
488:             offer = offerItems[itemIndex];
489: 
490:             
491:             if (!offer.isRental()) {
492:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
493:             }
494: 
495:             
496:             try
497:                 IHook(target).onStart(
498:                     rentalWallet,
499:                     offer.token,
500:                     offer.identifier,
501:                     offer.amount,
502:                     hooks[i].extraData
503:                 )
504:             {} catch Error(string memory revertReason) {
505:                 
506:                 revert Errors.Shared_HookFailString(revertReason);
507:             } catch Panic(uint256 errorCode) {
508:                 
509:                 string memory stringErrorCode = LibString.toString(errorCode);
510: 
511:                 
512:                 revert Errors.Shared_HookFailString(
513:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
514:                 );
515:             } catch (bytes memory revertData) {
516:                 
517:                 revert Errors.Shared_HookFailBytes(revertData);
518:             }
519:         }

```


*GitHub* : [475](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L475-L475)

```solidity
205:        for (uint256 i = 0; i < hooks.length; ++i) { // <= FOUND
206:             
207:             target = hooks[i].target;
208: 
209:             
210:             if (!STORE.hookOnStop(target)) {
211:                 revert Errors.Shared_DisabledHook(target);
212:             }
213: 
214:             
215:             itemIndex = hooks[i].itemIndex;
216: 
217:             
218:             item = rentalItems[itemIndex];
219: 
220:             
221:             if (!item.isRental()) {
222:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
223:             }
224: 
225:             
226:             try
227:                 IHook(target).onStop(
228:                     rentalWallet,
229:                     item.token,
230:                     item.identifier,
231:                     item.amount,
232:                     hooks[i].extraData
233:                 )
234:             {} catch Error(string memory revertReason) {
235:                 
236:                 revert Errors.Shared_HookFailString(revertReason);
237:             } catch Panic(uint256 errorCode) {
238:                 
239:                 string memory stringErrorCode = LibString.toString(errorCode);
240: 
241:                 
242:                 revert Errors.Shared_HookFailString(
243:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
244:                 );
245:             } catch (bytes memory revertData) {
246:                 
247:                 revert Errors.Shared_HookFailBytes(revertData);
248:             }
249:         }

```


*GitHub* : [205](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L205-L205)
### [L-21]<a name="l-21"></a> Address collision possible due to upcast
Upcasting addresses and comparing them to larger uint types can risk address collisions in smart contracts, potentially introducing vulnerabilities. Specifically, if a uint160 address is upcast to a uint256 and compared with larger values, the comparison may pass incorrectly if the larger value, when cast back down, matches the address. Therefore, checks designed to gate access to certain addresses might erroneously permit access when larger values are used. To mitigate this, ensure type consistency during comparisons—compare uint160 to uint160 and utilize explicit type conversions cautiously.

*There are 1 instance(s) of this issue:*

```solidity
94: 
95:         
96:         return address(uint160(uint256(addressHash))); // <= FOUND

```


*GitHub* : [94](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L94-L96)
### [L-22]<a name="l-22"></a> Use of abi.encodePacked with dynamic types inside keccak256
Using abi.encodePacked with dynamic types for hashing functions like keccak256 can be risky due to the potential for hash collisions. This function concatenates arguments tightly, without padding, which might lead to different inputs producing the same hash. This is especially problematic with dynamic types, where the boundaries between inputs can blur. To mitigate this, use abi.encode instead. abi.encode pads its arguments to 32 bytes, creating clear distinctions between different inputs and significantly reducing the chance of hash collisions. This approach ensures more reliable and collision-resistant hashing, crucial for maintaining data integrity and security in smart contracts.

*There are 2 instance(s) of this issue:*

```solidity
181: 
182:         return
183:             keccak256(
184:                 abi.encode(
185:                     _RENTAL_ORDER_TYPEHASH,
186:                     order.seaportOrderHash,
187:                     keccak256(abi.encodePacked(itemHashes)), // <= FOUND
188:                     keccak256(abi.encodePacked(hookHashes)), // <= FOUND
189:                     order.orderType,
190:                     order.lender,
191:                     order.renter,
192:                     order.startTimestamp,
193:                     order.endTimestamp
194:                 )
195:             );

```


*GitHub* : [187](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L187-L188)

```solidity
231: 
232:         
233:         return
234:             keccak256(
235:                 abi.encode(
236:                     _ORDER_METADATA_TYPEHASH,
237:                     metadata.rentDuration,
238:                     keccak256(abi.encodePacked(hookHashes)) // <= FOUND
239:                 )
240:             );

```


*GitHub* : [238](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L238-L238)
### [L-23]<a name="l-23"></a> Constructors missing validation
In Solidity, when values are being assigned in constructors to unsigned or integer variables, it's crucial to ensure the provided values adhere to the protocol's specific operational boundaries as laid out in the project specifications and documentation. If the constructors lack appropriate validation checks, there's a risk of setting state variables with values that could cause unexpected and potentially detrimental behavior within the contract's operations, violating the intended logic of the protocol. This can compromise the contract's security and impact the maintainability and reliability of the system. In order to avoid such issues, it is recommended to incorporate rigorous validation checks in constructors. These checks should align with the project's defined rules and constraints, making use of Solidity's built-in require function to enforce these conditions. If the validation checks fail, the require function will cause the transaction to revert, ensuring the integrity and adherence to the protocol's expected behavior.

*There are 3 instance(s) of this issue:*

```solidity
49:     constructor(
50:         Kernel kernel_,
51:         Stop stopPolicy_,
52:         Guard guardPolicy_,
53:         TokenCallbackHandler fallbackHandler_,
54:         SafeProxyFactory safeProxyFactory_,
55:         SafeL2 safeSingleton_
56:     ) Policy(kernel_) {
57:         stopPolicy = stopPolicy_; // <= FOUND ' = stopPolicy_;'
58:         guardPolicy = guardPolicy_; // <= FOUND ' = guardPolicy_;'
59:         fallbackHandler = fallbackHandler_; // <= FOUND ' = fallbackHandler_;'
60:         safeProxyFactory = safeProxyFactory_; // <= FOUND ' = safeProxyFactory_;'
61:         safeSingleton = safeSingleton_; // <= FOUND ' = safeSingleton_;'
62:     }

```


*GitHub* : [49](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L49-L61)

```solidity
33:     constructor(Kernel kernel_) {
34:         kernel = kernel_; // <= FOUND ' = kernel_;'
35:     }

```


*GitHub* : [33](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L33-L34)

```solidity
242:     constructor(address _executor, address _admin) {
243:         executor = _executor; // <= FOUND ' = _executor;'
244:         admin = _admin; // <= FOUND ' = _admin;'
245:     }

```


*GitHub* : [242](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L242-L244)
### [L-24]<a name="l-24"></a> Functions calling contracts/addresses with transfer hooks are missing reentrancy guards
While adherence to the check-effects-interaction pattern is commendable, the absence of a reentrancy guard in functions, especially where transfer hooks might be present, can expose the protocol users to risks of read-only reentrancies. Such reentrancy vulnerabilities can be exploited to execute malicious actions even without altering the contract state. Without a reentrancy guard, the only potential mitigation would be to blocklist the entire protocol - an extreme and disruptive measure. Therefore, incorporating a reentrancy guard into these functions is vital to bolster security, as it helps protect against both traditional reentrancy attacks and read-only reentrancies, ensuring robust and safe protocol operations.

*There are 3 instance(s) of this issue:*

```solidity
159:     function _settlePaymentProRata(
160:         address token,
161:         uint256 amount,
162:         address lender,
163:         address renter,
164:         uint256 elapsedTime,
165:         uint256 totalTime
166:     ) internal {
167:         
168:         (uint256 renterAmount, uint256 lenderAmount) = _calculatePaymentProRata(
169:             amount,
170:             elapsedTime,
171:             totalTime
172:         );
173: 
174:         
175:         _safeTransfer(token, lender, lenderAmount);
176: 
177:         
178:         _safeTransfer(token, renter, renterAmount);
179:     }

```


*GitHub* : [159](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L159-L159)

```solidity
190:     function _settlePaymentInFull(
191:         address token,
192:         uint256 amount,
193:         SettleTo settleTo,
194:         address lender,
195:         address renter
196:     ) internal {
197:         
198:         address settleToAddress = settleTo == SettleTo.LENDER ? lender : renter;
199: 
200:         
201:         _safeTransfer(token, settleToAddress, amount);
202:     }

```


*GitHub* : [190](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L190-L190)

```solidity
397:     function skim(address token, address to) external onlyByProxy permissioned { // <= FOUND
398:         
399:         uint256 syncedBalance = balanceOf[token];
400: 
401:         
402:         uint256 trueBalance = IERC20(token).balanceOf(address(this));
403: 
404:         
405:         uint256 skimmedBalance = trueBalance - syncedBalance;
406: 
407:         
408:         _safeTransfer(token, to, skimmedBalance);
409: 
410:         
411:         emit Events.FeeTaken(token, skimmedBalance);
412:     }

```


*GitHub* : [397](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L397-L397)
### [L-25]<a name="l-25"></a> Inconsistent checks of address params against address(0)
Only some address parameters are checked against address(0), to ensure consistency ensure all address parameters are checked.

*There are 1 instance(s) of this issue:*

```solidity
309:     function checkTransaction(
310:         address to, // <= FOUND 'address to'
311:         uint256 value,
312:         bytes memory data,
313:         Enum.Operation operation,
314:         uint256,
315:         uint256,
316:         uint256,
317:         address,
318:         address payable, // <= FOUND 'address payable'
319:         bytes memory,
320:         address
321:     ) external override {
322:         
323:         
324:         if (operation == Enum.Operation.DelegateCall && !STORE.whitelistedDelegates(to)) {
325:             revert Errors.GuardPolicy_UnauthorizedDelegateCall(to);
326:         }
327: 
328:         
329:         if (data.length < 4) {
330:             revert Errors.GuardPolicy_FunctionSelectorRequired();
331:         }
332: 
333:         
334:         address hook = STORE.contractToHook(to); // <= FOUND 'address hook'
335:         bool isActive = STORE.hookOnTransaction(hook);
336: 
337:         
338:         if (hook != address(0) && isActive) {
339:             _forwardToHook(hook, msg.sender, to, value, data);
340:         }
341:         
342:         else {
343:             _checkTransaction(msg.sender, to, data);
344:         }
345:     }

```


*GitHub* : [309](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L309-L334)
### [L-26]<a name="l-26"></a> Upgradeable contract uses non-upgradeable version of the OpenZeppelin libraries/contracts
Using the upgradeable counterpart of the OpenZeppelin (OZ) library in Solidity is beneficial for creating contracts that can be updated in the future. OpenZeppelin's upgradeable contracts library is designed with proxy patterns in mind, which allow the logic of contracts to be upgraded while preserving the contract's state and address. This can be crucial for long-lived contracts where future requirements or improvements may not be fully known at the time of deployment. The upgradeable OZ contracts also include protection against a class of vulnerabilities related to initialization of storage variables in upgradeable contracts. Hence, it's a good idea to use them when developing contracts that may need to be upgraded in the future, as they provide a solid foundation for secure and upgradeable smart contracts.

*There are 4 instance(s) of this issue:*

```solidity
4: import {IERC721} from "@openzeppelin-contracts/token/ERC721/IERC721.sol"; // <= FOUND 'openzeppelin'

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L4-L4)

```solidity
4: import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol"; // <= FOUND 'openzeppelin'

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L4-L4)

```solidity
5: import {IERC1155} from "@openzeppelin-contracts/token/ERC1155/IERC1155.sol"; // <= FOUND 'openzeppelin'

```


*GitHub* : [5](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L5-L5)

```solidity
4: import {ECDSA} from "@openzeppelin-contracts/utils/cryptography/ECDSA.sol"; // <= FOUND 'openzeppelin'

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L4-L4)
### [L-27]<a name="l-27"></a> Functions calling contracts/addresses with transfer hooks are missing reentrancy guards
While adherence to the check-effects-interaction pattern is commendable, the absence of a reentrancy guard in functions, especially where transfer hooks might be present, can expose the protocol users to risks of read-only reentrancies. Such reentrancy vulnerabilities can be exploited to execute malicious actions even without altering the contract state. Without a reentrancy guard, the only potential mitigation would be to blocklist the entire protocol - an extreme and disruptive measure. Therefore, incorporating a reentrancy guard into these functions is vital to bolster security, as it helps protect against both traditional reentrancy attacks and read-only reentrancies, ensuring robust and safe protocol operations.

*There are 3 instance(s) of this issue:*

```solidity
159:     function _settlePaymentProRata(
160:         address token,
161:         uint256 amount,
162:         address lender,
163:         address renter,
164:         uint256 elapsedTime,
165:         uint256 totalTime
166:     ) internal {
167:         
168:         (uint256 renterAmount, uint256 lenderAmount) = _calculatePaymentProRata(
169:             amount,
170:             elapsedTime,
171:             totalTime
172:         );
173: 
174:         
175:         _safeTransfer(token, lender, lenderAmount); // <= FOUND
176: 
177:         
178:         _safeTransfer(token, renter, renterAmount); // <= FOUND
179:     }

```


*GitHub* : [159](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L159-L178)

```solidity
190:     function _settlePaymentInFull(
191:         address token,
192:         uint256 amount,
193:         SettleTo settleTo,
194:         address lender,
195:         address renter
196:     ) internal {
197:         
198:         address settleToAddress = settleTo == SettleTo.LENDER ? lender : renter;
199: 
200:         
201:         _safeTransfer(token, settleToAddress, amount); // <= FOUND
202:     }

```


*GitHub* : [190](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L190-L201)

```solidity
397:     function skim(address token, address to) external onlyByProxy permissioned {
398:         
399:         uint256 syncedBalance = balanceOf[token];
400: 
401:         
402:         uint256 trueBalance = IERC20(token).balanceOf(address(this));
403: 
404:         
405:         uint256 skimmedBalance = trueBalance - syncedBalance;
406: 
407:         
408:         _safeTransfer(token, to, skimmedBalance); // <= FOUND
409: 
410:         
411:         emit Events.FeeTaken(token, skimmedBalance);
412:     }

```


*GitHub* : [397](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L397-L408)
### [L-28]<a name="l-28"></a> Upgradable contracts not taken into account
When wrapping a token address with interfaces like IERC20 for external calls, especially in the context of upgradable contracts, it's essential to account for the potential changes these tokens might undergo. Upgrades can modify a token's behavior or interface, which could introduce compatibility issues or vulnerabilities in the interacting protocol.

**Resolution:**
To manage this risk, integrate an allowlist system in your protocol. This system would monitor for upgrades in token contracts. Upon detecting an upgrade, the corresponding token contract would be automatically removed from the allowlist, suspending its interaction with your protocol. The contract can only be re-added to the allowlist after a thorough review to confirm its continued compatibility and safety post-upgrade. This approach helps maintain a secure and adaptable protocol, ensuring it only interacts with verified, stable versions of external contracts. Regular audits and ongoing monitoring of these external contracts are vital for maintaining the integrity and security of the protocol.

*There are 1 instance(s) of this issue:*

```solidity
397:     function skim(address token, address to) external onlyByProxy permissioned { // <= FOUND
398:         
399:         uint256 syncedBalance = balanceOf[token];
400: 
401:         
402:         uint256 trueBalance = IERC20(token).balanceOf(address(this));
403: 
404:         
405:         uint256 skimmedBalance = trueBalance - syncedBalance;
406: 
407:         
408:         _safeTransfer(token, to, skimmedBalance);
409: 
410:         
411:         emit Events.FeeTaken(token, skimmedBalance);
412:     }

```


*GitHub* : [397](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L397-L397)### Gas Risk Issues


### [G-01]<a name="g-01"></a> Consider merging sequential for loops 
Merging multiple `for` loops within a function in Solidity can enhance efficiency and reduce gas costs, especially when they share a common iterating variable or perform related operations. By minimizing redundant iterations over the same data set, execution becomes more cost-effective. However, while merging can optimize gas usage and simplify logic, it may also increase code complexity. Therefore, careful balance between optimization and maintainability is essential, along with thorough testing to ensure the refactored code behaves as expected.

*There are 1 instance(s) of this issue:*

```solidity
530:     function _rentFromZone(
531:         RentPayload memory payload,
532:         SeaportPayload memory seaportPayload
533:     ) internal {
534:         
535:         _isValidOrderMetadata(payload.metadata, seaportPayload.zoneHash);
536: 
537:         
538:         _isValidSafeOwner(seaportPayload.fulfiller, payload.fulfillment.recipient);
539: 
540:         
541:         _executionInvariantChecks(
542:             seaportPayload.totalExecutions,
543:             payload.fulfillment.recipient
544:         );
545: 
546:         
547:         
548:         Item[] memory items = _convertToItems(
549:             seaportPayload.offer,
550:             seaportPayload.consideration,
551:             payload.metadata.orderType
552:         );
553: 
554:         
555:         
556:         if (
557:             payload.metadata.orderType.isBaseOrder() ||
558:             payload.metadata.orderType.isPayOrder()
559:         ) {
560:             
561:             
562:             
563:             bytes memory rentalAssetUpdates = new bytes(0);
564: 
565:             
566:             
567:             for (uint256 i; i < items.length; ++i) { // <= FOUND
568:                 if (items[i].isRental()) {
569:                     
570:                     _insert(
571:                         rentalAssetUpdates,
572:                         items[i].toRentalId(payload.fulfillment.recipient),
573:                         items[i].amount
574:                     );
575:                 }
576:             }
577: 
578:             
579:             RentalOrder memory order = RentalOrder({
580:                 seaportOrderHash: seaportPayload.orderHash,
581:                 items: items,
582:                 hooks: payload.metadata.hooks,
583:                 orderType: payload.metadata.orderType,
584:                 lender: seaportPayload.offerer,
585:                 renter: payload.intendedFulfiller,
586:                 rentalWallet: payload.fulfillment.recipient,
587:                 startTimestamp: block.timestamp,
588:                 endTimestamp: block.timestamp + payload.metadata.rentDuration
589:             });
590: 
591:             
592:             bytes32 orderHash = _deriveRentalOrderHash(order);
593: 
594:             
595:             STORE.addRentals(orderHash, _convertToStatic(rentalAssetUpdates));
596: 
597:             
598:             
599:             for (uint256 i = 0; i < items.length; ++i) { // <= FOUND
600:                 if (items[i].isERC20()) {
601:                     ESCRW.increaseDeposit(items[i].token, items[i].amount);
602:                 }
603:             }
604: 
605:             
606:             if (payload.metadata.hooks.length > 0) {
607:                 _addHooks(
608:                     payload.metadata.hooks,
609:                     seaportPayload.offer,
610:                     payload.fulfillment.recipient
611:                 );
612:             }
613: 
614:             
615:             _emitRentalOrderStarted(order, orderHash, payload.metadata.emittedExtraData);
616:         }
617:     }

```


*GitHub* : [530](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L530-L599)
### [G-02]<a name="g-02"></a> Lack of unchecked in loops 
In Solidity, the `unchecked` block allows arithmetic operations to not revert on overflow. Without using `unchecked` in loops, extra gas is consumed due to overflow checks. If it's certain that overflows won't occur within the loop, using `unchecked` can make the loop more gas-efficient by skipping unnecessary checks.

*There are 18 instance(s) of this issue:*

```solidity
231:        for (uint256 i = 0; i < items.length; ++i) {
232:             
233:             Item memory item = items[i];
234: 
235:             
236:             if (item.isERC20()) {
237:                 
238:                 
239:                 uint256 paymentAmount = item.amount;
240: 
241:                 
242:                 if (fee != 0) {
243:                     
244:                     uint256 paymentFee = _calculateFee(paymentAmount);
245: 
246:                     
247:                     paymentAmount -= paymentFee;
248:                 }
249: 
250:                 
251:                 
252:                 _decreaseDeposit(item.token, item.amount);
253: 
254:                 
255:                 if (orderType.isPayOrder() && !isRentalOver) {
256:                     
257:                     _settlePaymentProRata(
258:                         item.token,
259:                         paymentAmount,
260:                         lender,
261:                         renter,
262:                         elapsedTime,
263:                         totalTime
264:                     );
265:                 }
266:                 
267:                 else if (
268:                     (orderType.isPayOrder() && isRentalOver) || orderType.isBaseOrder()
269:                 ) {
270:                     
271:                     _settlePaymentInFull(
272:                         item.token,
273:                         paymentAmount,
274:                         item.settleTo,
275:                         lender,
276:                         renter
277:                     );
278:                 } else {
279:                     revert Errors.Shared_OrderTypeNotSupported(uint8(orderType));
280:                 }
281:             }
282:         }

```


*GitHub* : [231](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L231-L231)

```solidity
341:        for (uint256 i = 0; i < orders.length; ++i) {
342:             
343:             _settlePayment(
344:                 orders[i].items,
345:                 orders[i].orderType,
346:                 orders[i].lender,
347:                 orders[i].renter,
348:                 orders[i].startTimestamp,
349:                 orders[i].endTimestamp
350:             );
351:         }

```


*GitHub* : [341](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L341-L341)

```solidity
197:        for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {
198:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
199: 
200:             
201:             rentedAssets[asset.rentalId] += asset.amount;
202:         }

```


*GitHub* : [197](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L197-L197)

```solidity
249:        for (uint256 i = 0; i < orderHashes.length; ++i) {
250:             
251:             if (!orders[orderHashes[i]]) {
252:                 revert Errors.StorageModule_OrderDoesNotExist(orderHashes[i]);
253:             } else {
254:                 
255:                 delete orders[orderHashes[i]];
256:             }
257:         }

```


*GitHub* : [249](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L249-L249)

```solidity
170:        for (uint256 i = 0; i < order.items.length; ++i) {
171:             
172:             itemHashes[i] = _deriveItemHash(order.items[i]);
173:         }

```


*GitHub* : [170](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L170-L170)

```solidity
225:        for (uint256 i = 0; i < metadata.hooks.length; ++i) {
226:             
227:             hookHashes[i] = _deriveHookHash(metadata.hooks[i]);
228:         }

```


*GitHub* : [225](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L225-L225)

```solidity
261:        for (uint256 i; i < offers.length; ++i) {
262:             
263:             SpentItem memory offer = offers[i];
264: 
265:             
266:             if (offer.isERC721()) {
267:                 
268:                 
269:                 itemType = ItemType.ERC721;
270:                 settleTo = SettleTo.LENDER;
271: 
272:                 
273:                 totalRentals++;
274:             }
275:             
276:             else if (offer.isERC1155()) {
277:                 
278:                 
279:                 itemType = ItemType.ERC1155;
280:                 settleTo = SettleTo.LENDER;
281: 
282:                 
283:                 totalRentals++;
284:             }
285:             
286:             else if (offer.isERC20()) {
287:                 
288:                 
289:                 itemType = ItemType.ERC20;
290:                 settleTo = SettleTo.RENTER;
291: 
292:                 
293:                 totalPayments++;
294:             }
295:             
296:             else {
297:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(offer.itemType);
298:             }
299: 
300:             
301:             rentalItems[i + startIndex] = Item({
302:                 itemType: itemType,
303:                 settleTo: settleTo,
304:                 token: offer.token,
305:                 amount: offer.amount,
306:                 identifier: offer.identifier
307:             });
308:         }

```


*GitHub* : [261](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L261-L261)

```solidity
375:        for (uint256 i; i < considerations.length; ++i) {
376:             
377:             ReceivedItem memory consideration = considerations[i];
378: 
379:             
380:             if (consideration.isERC20()) {
381:                 totalPayments++;
382:             }
383:             
384:             else if (consideration.isRental()) {
385:                 totalRentals++;
386:             }
387:             
388:             else {
389:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
390:                     consideration.itemType
391:                 );
392:             }
393:         }

```


*GitHub* : [375](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L375-L375)

```solidity
475:        for (uint256 i = 0; i < hooks.length; ++i) {
476:             
477:             target = hooks[i].target;
478: 
479:             
480:             if (!STORE.hookOnStart(target)) {
481:                 revert Errors.Shared_DisabledHook(target);
482:             }
483: 
484:             
485:             itemIndex = hooks[i].itemIndex;
486: 
487:             
488:             offer = offerItems[itemIndex];
489: 
490:             
491:             if (!offer.isRental()) {
492:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
493:             }
494: 
495:             
496:             try
497:                 IHook(target).onStart(
498:                     rentalWallet,
499:                     offer.token,
500:                     offer.identifier,
501:                     offer.amount,
502:                     hooks[i].extraData
503:                 )
504:             {} catch Error(string memory revertReason) {
505:                 
506:                 revert Errors.Shared_HookFailString(revertReason);
507:             } catch Panic(uint256 errorCode) {
508:                 
509:                 string memory stringErrorCode = LibString.toString(errorCode);
510: 
511:                 
512:                 revert Errors.Shared_HookFailString(
513:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
514:                 );
515:             } catch (bytes memory revertData) {
516:                 
517:                 revert Errors.Shared_HookFailBytes(revertData);
518:             }
519:         }

```


*GitHub* : [475](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L475-L475)

```solidity
695:        for (uint256 i = 0; i < executions.length; ++i) {
696:             ReceivedItem memory execution = executions[i];
697: 
698:             
699:             if (execution.isERC20()) {
700:                 _checkExpectedRecipient(execution, address(ESCRW));
701:             }
702:             
703:             
704:             else if (execution.isRental()) {
705:                 _checkExpectedRecipient(execution, expectedRentalSafe);
706:             }
707:             
708:             else {
709:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
710:                     execution.itemType
711:                 );
712:             }
713:         }

```


*GitHub* : [695](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L695-L695)

```solidity
205:        for (uint256 i = 0; i < hooks.length; ++i) {
206:             
207:             target = hooks[i].target;
208: 
209:             
210:             if (!STORE.hookOnStop(target)) {
211:                 revert Errors.Shared_DisabledHook(target);
212:             }
213: 
214:             
215:             itemIndex = hooks[i].itemIndex;
216: 
217:             
218:             item = rentalItems[itemIndex];
219: 
220:             
221:             if (!item.isRental()) {
222:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
223:             }
224: 
225:             
226:             try
227:                 IHook(target).onStop(
228:                     rentalWallet,
229:                     item.token,
230:                     item.identifier,
231:                     item.amount,
232:                     hooks[i].extraData
233:                 )
234:             {} catch Error(string memory revertReason) {
235:                 
236:                 revert Errors.Shared_HookFailString(revertReason);
237:             } catch Panic(uint256 errorCode) {
238:                 
239:                 string memory stringErrorCode = LibString.toString(errorCode);
240: 
241:                 
242:                 revert Errors.Shared_HookFailString(
243:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
244:                 );
245:             } catch (bytes memory revertData) {
246:                 
247:                 revert Errors.Shared_HookFailBytes(revertData);
248:             }
249:         }

```


*GitHub* : [205](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L205-L205)

```solidity
276:        for (uint256 i; i < order.items.length; ++i) {
277:             if (order.items[i].isRental()) {
278:                 
279:                 _insert(
280:                     rentalAssetUpdates,
281:                     order.items[i].toRentalId(order.rentalWallet),
282:                     order.items[i].amount
283:                 );
284:             }
285:         }

```


*GitHub* : [276](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L276-L276)

```solidity
324:        for (uint256 i = 0; i < orders.length; ++i) {
325:             
326:             _validateRentalCanBeStoped(
327:                 orders[i].orderType,
328:                 orders[i].endTimestamp,
329:                 orders[i].lender
330:             );
331: 
332:             
333:             for (uint256 j = 0; j < orders[i].items.length; ++j) {
334:                 
335:                 if (orders[i].items[j].isRental()) {
336:                     _insert(
337:                         rentalAssetUpdates,
338:                         orders[i].items[j].toRentalId(orders[i].rentalWallet),
339:                         orders[i].items[j].amount
340:                     );
341:                 }
342:             }
343: 
344:             
345:             orderHashes[i] = _deriveRentalOrderHash(orders[i]);
346: 
347:             
348:             if (orders[i].hooks.length > 0) {
349:                 _removeHooks(orders[i].hooks, orders[i].items, orders[i].rentalWallet);
350:             }
351: 
352:             
353:             _reclaimRentedItems(orders[i]);
354: 
355:             
356:             _emitRentalOrderStopped(orderHashes[i], msg.sender);
357:         }

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L324-L324)

```solidity
438:        for (uint256 i; i < depLength; ++i) {
439:             Keycode keycode = dependencies[i];
440: 
441:             
442:             moduleDependents[keycode].push(policy_);
443: 
444:             
445:             getDependentIndex[keycode][policy_] = moduleDependents[keycode].length - 1;
446:         }

```


*GitHub* : [438](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L438-L438)

```solidity
512:        for (uint256 i; i < keycodeLen; ++i) {
513:             
514:             Module module = Module(getModuleForKeycode[allKeycodes[i]]);
515:             
516:             module.changeKernel(newKernel_);
517:         }

```


*GitHub* : [512](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L512-L512)

```solidity
546:        for (uint256 i; i < depLength; ++i) {
547:             
548:             dependents[i].configureDependencies();
549:         }

```


*GitHub* : [546](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L546-L546)

```solidity
566:        for (uint256 i = 0; i < reqLength; ++i) {
567:             
568:             Permissions memory request = requests_[i];
569:             modulePermissions[request.keycode][policy_][request.funcSelector] = grant_;
570: 
571:             emit Events.PermissionsUpdated(
572:                 request.keycode,
573:                 policy_,
574:                 request.funcSelector,
575:                 grant_
576:             );
577:         }

```


*GitHub* : [566](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L566-L566)

```solidity
592:        for (uint256 i; i < depcLength; ++i) {
593:             
594:             Keycode keycode = dependencies[i];
595:             Policy[] storage dependents = moduleDependents[keycode];
596: 
597:             
598:             uint256 origIndex = getDependentIndex[keycode][policy_];
599: 
600:             
601:             Policy lastPolicy = dependents[dependents.length - 1];
602: 
603:             
604:             dependents[origIndex] = lastPolicy;
605: 
606:             
607:             
608:             dependents.pop();
609: 
610:             
611:             getDependentIndex[keycode][lastPolicy] = origIndex;
612: 
613:             
614:             delete getDependentIndex[keycode][policy_];
615:         }

```


*GitHub* : [592](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L592-L592)
### [G-03]<a name="g-03"></a> Multiple accesses of the same mapping/array key/index should be cached 
Caching repeated accesses to the same mapping or array key/index in smart contracts can lead to significant gas savings. In Solidity, each read operation from storage (like accessing a value in a mapping or array using a key or index) costs gas. By storing the accessed value in a local variable and reusing it within the function, you avoid multiple expensive storage read operations. This practice is particularly beneficial in loops or functions with multiple reads of the same data. Implementing this caching approach enhances efficiency and reduces transaction costs, which is crucial for optimizing smart contract performance and user experience on the blockchain.

*There are 1 instance(s) of this issue:*

```solidity
356:     function _installModule(Module newModule_) internal {
357:         
358:         Keycode keycode = newModule_.KEYCODE();
359: 
360:         
361:         if (address(getModuleForKeycode[keycode]) != address(0)) { // <= FOUND
362:             revert Errors.Kernel_ModuleAlreadyInstalled(keycode);
363:         }
364: 
365:         
366:         getModuleForKeycode[keycode] = newModule_; // <= FOUND
367: 
368:         
369:         getKeycodeForModule[newModule_] = keycode;
370: 
371:         
372:         allKeycodes.push(keycode);
373: 
374:         
375:         newModule_.INIT();
376:     }

```


*GitHub* : [356](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L356-L366)
### [G-04]<a name="g-04"></a> Shorten the array rather than copying to a new one 
Leveraging inline assembly in Solidity provides the ability to directly manipulate the length slot of an array, thereby altering its length without the need to copy the elements to a new array of the desired size. This technique is more gas-efficient as it avoids the computational expense associated with array duplication. However, this method circumvents the type-checking and safety mechanisms of high-level Solidity and should be used judiciously. Always ensure that the array doesn't contain vital data beyond the revised length, as this data will become unreachable yet still consume storage space.

*There are 12 instance(s) of this issue:*

```solidity
116: 
117:         
118:         updates = new RentalAssetUpdate[](rentalAssetUpdateLength); // <= FOUND

```


*GitHub* : [116](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L116-L118)

```solidity
166:         
167:         bytes32[] memory itemHashes = new bytes32[](order.items.length); // <= FOUND

```


*GitHub* : [166](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L166-L167)

```solidity
167:         bytes32[] memory hookHashes = new bytes32[](order.hooks.length); // <= FOUND

```


*GitHub* : [167](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L167-L167)

```solidity
222:         
223:         bytes32[] memory hookHashes = new bytes32[](metadata.hooks.length); // <= FOUND

```


*GitHub* : [222](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L222-L223)

```solidity
78:         dependencies = new Keycode[](2); // <= FOUND

```


*GitHub* : [78](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L78-L78)

```solidity
71:         requests = new Permissions[](8); // <= FOUND

```


*GitHub* : [71](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L71-L71)

```solidity
103:         requests = new Permissions[](2); // <= FOUND

```


*GitHub* : [103](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L103-L103)

```solidity
417:         
418:         items = new Item[](offers.length + considerations.length); // <= FOUND

```


*GitHub* : [417](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L417-L418)

```solidity
79:         dependencies = new Keycode[](1); // <= FOUND

```


*GitHub* : [79](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L79-L79)

```solidity
101:         requests = new Permissions[](1); // <= FOUND

```


*GitHub* : [101](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L101-L101)

```solidity
94:         requests = new Permissions[](4); // <= FOUND

```


*GitHub* : [94](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L94-L94)

```solidity
315:         
316:         bytes32[] memory orderHashes = new bytes32[](orders.length); // <= FOUND

```


*GitHub* : [315](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L315-L316)
### [G-05]<a name="g-05"></a> Using bools for storage incurs overhead 
Using boolean variables (`bool`) for storage in Solidity can incur overhead due to the way data is packed in Ethereum's storage layout. A `bool` takes a full storage slot, even though it represents only a true or false value. This leads to inefficient usage of storage space and potentially higher gas costs. To resolve this issue, developers can use bit fields or uint8/uint256 to pack multiple boolean values into a single storage slot. By employing such optimization techniques, it's possible to save on storage space and reduce gas costs, making the contract more efficient.

*There are 5 instance(s) of this issue:*

```solidity
228: 
229:         
230:         bool isRentalOver = elapsedTime >= totalTime; // <= FOUND

```


*GitHub* : [228](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L228-L230)

```solidity
335:         bool isActive = STORE.hookOnTransaction(hook); // <= FOUND

```


*GitHub* : [335](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L335-L335)

```solidity
132:         
133:         bool hasExpired = endTimestamp <= block.timestamp; // <= FOUND

```


*GitHub* : [132](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L132-L133)

```solidity
135: 
136:         
137:         bool isLender = expectedLender == msg.sender; // <= FOUND

```


*GitHub* : [135](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L135-L137)

```solidity
116:     
117:     bool public isActive; // <= FOUND

```


*GitHub* : [116](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L116-L117)
### [G-06]<a name="g-06"></a> Low level call can be optimized with assembly
Low-level calls, when optimized with assembly, can save gas by avoiding unnecessary operations related to unused returndata. In a typical `.call`, Solidity automatically allocates memory and handles returndata even if it's not used, incurring extra gas costs. By using assembly, a developer can precisely control the execution, selectively ignoring or handling returndata, thereby optimizing gas usage. This specific control over the EVM allows for more efficient execution of calls by eliminating unnecessary memory operations, providing a more gas-efficient method when unused returndata is a concern. However, such optimization should be handled with care, as improper use of assembly might lead to vulnerabilities.

*There are 1 instance(s) of this issue:*

```solidity
102:         
103:         (bool success, bytes memory data) = token.call( // <= FOUND
104:             abi.encodeWithSelector(IERC20.transfer.selector, to, value)
105:         );

```


*GitHub* : [103](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L103-L103)
### [G-07]<a name="g-07"></a> Optimize by Using Assembly for Low-Level Calls' Return Data
Using assembly for low-level calls in Solidity can provide gas savings, especially when dealing with return data. High-level Solidity calls include overhead for decoding return data, which can be bypassed with assembly. By directly accessing return data in assembly, you can eliminate unnecessary memory allocation and data copying, leading to a more gas-efficient execution. However, this approach requires a deep understanding of the Ethereum Virtual Machine (EVM) and is prone to errors. It’s crucial to ensure security and correctness in the implementation. This technique is best suited for advanced users aiming to optimize contract performance in specific, gas-critical scenarios.

*There are 1 instance(s) of this issue:*

```solidity
102:         
103:         (bool success, bytes memory data) = token.call( // <= FOUND
104:             abi.encodeWithSelector(IERC20.transfer.selector, to, value)
105:         );

```


*GitHub* : [102](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L102-L103)
### [G-08]<a name="g-08"></a> Public functions not used internally can be marked as external to save gas
Public functions that aren't used internally in Solidity contracts should be made external to optimize gas usage and improve contract efficiency. External functions can only be called from outside the contract, and their arguments are directly read from the calldata, which is more gas-efficient than loading them into memory, as is the case for public functions. By using external visibility, developers can reduce gas consumption for external calls and ensure that the contract operates more cost-effectively for users. Moreover, setting the appropriate visibility level for functions also enhances code readability and maintainability, promoting a more secure and well-structured contract design.

*There are 3 instance(s) of this issue:*

```solidity
107:     function generateSaltWithSender(
108:         address sender,
109:         bytes12 data
110:     ) public pure returns (bytes32 salt) 

```


*GitHub* : [107](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L107-L107)

```solidity
310:     function grantRole(Role role_, address addr_) public onlyAdmin 

```


*GitHub* : [310](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L310-L310)

```solidity
333:     function revokeRole(Role role_, address addr_) public onlyAdmin 

```


*GitHub* : [333](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L333-L333)
### [G-09]<a name="g-09"></a> Calldata should be used in place of memory function parameters when not mutated
In Solidity, `calldata` should be used in place of `memory` for function parameters when the function is `external`. This is because `calldata` is a non-modifiable, non-persistent area where function arguments are stored, and it's cheaper in terms of gas than `memory`. It's especially efficient for arrays and complex data types. `calldata` provides a gas-efficient way to pass data in external function calls, whereas `memory` is a temporary space that's erased between external function calls. This distinction is crucial for optimizing smart contracts for gas usage and performance.

*There are 1 instance(s) of this issue:*

```solidity
189:     function addRentals(
190:         bytes32 orderHash, // <= FOUND
191:         RentalAssetUpdate[] memory rentalAssetUpdates // <= FOUND
192:     ) external onlyByProxy permissioned {
193:         
194:         orders[orderHash] = true; // <= FOUND
195: 
196:         
197:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) { // <= FOUND
198:             RentalAssetUpdate memory asset = rentalAssetUpdates[i]; // <= FOUND
199: 
200:             
201:             rentedAssets[asset.rentalId] += asset.amount;
202:         }
203:     }

```


*GitHub* : [189](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L189-L198)
### [G-10]<a name="g-10"></a> Nested for loops should be avoided due to high gas costs resulting from O^2 time complexity
In Solidity, avoiding nested for loops is a recommended practice primarily due to the high gas costs associated with them. These loops can lead to quadratic (O^2) time complexity, especially when they iterate over large data sets or perform complex computations. Since every operation in a smart contract consumes gas, and users pay for this gas, optimizing for lower gas usage is crucial. Nested loops, which inherently have higher computational complexity, can significantly increase the gas costs of a contract. To optimize for efficiency, it's advisable to minimize the use of loops, limit their range, and reduce computations within each loop iteration. Alternative patterns like map/filter/reduce might often be cheaper than traditional for loops in terms of gas usage

*There are 1 instance(s) of this issue:*

```solidity
324:        for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND
325:             
326:             _validateRentalCanBeStoped(
327:                 orders[i].orderType,
328:                 orders[i].endTimestamp,
329:                 orders[i].lender
330:             );
331: 
332:             
333:             for (uint256 j = 0; j < orders[i].items.length; ++j) { // <= FOUND
334:                 
335:                 if (orders[i].items[j].isRental()) {
336:                     _insert(
337:                         rentalAssetUpdates,
338:                         orders[i].items[j].toRentalId(orders[i].rentalWallet),
339:                         orders[i].items[j].amount
340:                     );
341:                 }
342:             }
343: 
344:             
345:             orderHashes[i] = _deriveRentalOrderHash(orders[i]);
346: 
347:             
348:             if (orders[i].hooks.length > 0) { // <= FOUND
349:                 _removeHooks(orders[i].hooks, orders[i].items, orders[i].rentalWallet);
350:             }
351: 
352:             
353:             _reclaimRentedItems(orders[i]);
354: 
355:             
356:             _emitRentalOrderStopped(orderHashes[i], msg.sender);
357:         }

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L324-L348)
### [G-11]<a name="g-11"></a> Usage of smaller uint/int types causes overhead
When using a smaller int/uint type it first needs to be converted to it's 258 bit counterpart to be operated, this increases the gass cost and thus should be avoided. However it does make sense to use smaller int/uint values within structs provided you pack the struct properly.

*There are 5 instance(s) of this issue:*

```solidity
96:     function VERSION() external pure override returns (uint8 major, uint8 minor) { // <= FOUND
97:         return (1, 0);
98:     }

```


*GitHub* : [96](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L96-L96)

```solidity
313:     function updateHookStatus(
314:         address hook,
315:         uint8 bitmap // <= FOUND
316:     ) external onlyByProxy permissioned {
317:         
318:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook);
319: 
320:         
321:         if (bitmap > uint8(7))
322:             revert Errors.StorageModule_InvalidHookStatusBitmap(bitmap);
323: 
324:         
325:         hookStatus[hook] = bitmap;
326:     }

```


*GitHub* : [315](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L315-L315)

```solidity
339:     function _deriveRentalTypehashes()
340:         internal
341:         pure
342:         returns (
343:             bytes32 itemTypeHash,
344:             bytes32 hookTypeHash,
345:             bytes32 rentalOrderTypeHash,
346:             bytes32 orderFulfillmentTypeHash,
347:             bytes32 orderMetadataTypeHash,
348:             bytes32 rentPayloadTypeHash
349:         )
350:     {
351:         
352:         bytes memory itemTypeString = abi.encodePacked(
353:             "Item(uint8 itemType,uint8 settleTo,address token,uint256 amount,uint256 identifier)" // <= FOUND
354:         );
355: 
356:         
357:         bytes memory hookTypeString = abi.encodePacked(
358:             "Hook(address target,uint256 itemIndex,bytes extraData)"
359:         );
360: 
361:         
362:         bytes memory rentalOrderTypeString = abi.encodePacked(
363:             "RentalOrder(bytes32 seaportOrderHash,Item[] items,Hook[] hooks,uint8 orderType,address lender,address renter,address rentalWallet,uint256 startTimestamp,uint256 endTimestamp)" // <= FOUND
364:         );
365: 
366:         
367:         itemTypeHash = keccak256(itemTypeString);
368: 
369:         
370:         hookTypeHash = keccak256(hookTypeString);
371: 
372:         
373:         rentalOrderTypeHash = keccak256(
374:             abi.encode(rentalOrderTypeString, hookTypeString, itemTypeString)
375:         );
376: 
377:         {
378:             
379:             bytes memory orderFulfillmentTypeString = abi.encodePacked(
380:                 "OrderFulfillment(address recipient)"
381:             );
382: 
383:             
384:             bytes memory orderMetadataTypeString = abi.encodePacked(
385:                 "OrderMetadata(uint8 orderType,uint256 rentDuration,Hook[] hooks,bytes emittedExtraData)" // <= FOUND
386:             );
387: 
388:             
389:             bytes memory rentPayloadTypeString = abi.encodePacked(
390:                 "RentPayload(OrderFulfillment fulfillment,OrderMetadata metadata,uint256 expiration,address intendedFulfiller)"
391:             );
392: 
393:             
394:             rentPayloadTypeHash = keccak256(
395:                 abi.encodePacked(
396:                     rentPayloadTypeString,
397:                     orderMetadataTypeString,
398:                     orderFulfillmentTypeString
399:                 )
400:             );
401: 
402:             
403:             orderFulfillmentTypeHash = keccak256(orderFulfillmentTypeString);
404: 
405:             
406:             orderMetadataTypeHash = keccak256(orderMetadataTypeString);
407:         }
408:     }

```


*GitHub* : [353](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L353-L385)

```solidity
373:     function updateHookStatus(
374:         address hook,
375:         uint8 bitmap // <= FOUND
376:     ) external onlyRole("GUARD_ADMIN") {
377:         STORE.updateHookStatus(hook, bitmap);
378:     }

```


*GitHub* : [375](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L375-L375)

```solidity
100:     function VERSION() external pure virtual returns (uint8 major, uint8 minor) {} // <= FOUND

```


*GitHub* : [100](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L100-L100)
### [G-12]<a name="g-12"></a> Use != 0 instead of > 0
Replace spotted instances with != 0 for uints as this uses less gas

*There are 5 instance(s) of this issue:*

```solidity
433: 
434:             
435:             if (considerations.length > 0) { // <= FOUND

```


*GitHub* : [435](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L435-L435)

```solidity
442:             
443:             if (offers.length > 0) { // <= FOUND

```


*GitHub* : [443](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L443-L443)

```solidity
606: 
607:             
608:             if (payload.metadata.hooks.length > 0) { // <= FOUND

```


*GitHub* : [608](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L608-L608)

```solidity
288: 
289:         
290:         if (order.hooks.length > 0) { // <= FOUND

```


*GitHub* : [290](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L290-L290)

```solidity
348: 
349:             
350:             if (orders[i].hooks.length > 0) { // <= FOUND

```


*GitHub* : [350](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L350-L350)
### [G-13]<a name="g-13"></a> Integer increments by one can be unchecked to save on gas fees
Using unchecked increments in Solidity can save on gas fees by bypassing built-in overflow checks, thus optimizing gas usage, but requires careful assessment of potential risks and edge cases to avoid unintended consequences.

*There are 24 instance(s) of this issue:*

```solidity
215:     function _settlePayment(
216:         Item[] calldata items,
217:         OrderType orderType,
218:         address lender,
219:         address renter,
220:         uint256 start,
221:         uint256 end
222:     ) internal {
223:         
224:         uint256 elapsedTime = block.timestamp - start;
225:         uint256 totalTime = end - start;
226: 
227:         
228:         bool isRentalOver = elapsedTime >= totalTime;
229: 
230:         
231:         for (uint256 i = 0; i < items.length; ++i) { // <= FOUND
232:             
233:             Item memory item = items[i];
234: 
235:             
236:             if (item.isERC20()) {
237:                 
238:                 
239:                 uint256 paymentAmount = item.amount;
240: 
241:                 
242:                 if (fee != 0) {
243:                     
244:                     uint256 paymentFee = _calculateFee(paymentAmount);
245: 
246:                     
247:                     paymentAmount -= paymentFee;
248:                 }
249: 
250:                 
251:                 
252:                 _decreaseDeposit(item.token, item.amount);
253: 
254:                 
255:                 if (orderType.isPayOrder() && !isRentalOver) {
256:                     
257:                     _settlePaymentProRata(
258:                         item.token,
259:                         paymentAmount,
260:                         lender,
261:                         renter,
262:                         elapsedTime,
263:                         totalTime
264:                     );
265:                 }
266:                 
267:                 else if (
268:                     (orderType.isPayOrder() && isRentalOver) || orderType.isBaseOrder()
269:                 ) {
270:                     
271:                     _settlePaymentInFull(
272:                         item.token,
273:                         paymentAmount,
274:                         item.settleTo,
275:                         lender,
276:                         renter
277:                     );
278:                 } else {
279:                     revert Errors.Shared_OrderTypeNotSupported(uint8(orderType));
280:                 }

```


*GitHub* : [231](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L231-L231)

```solidity
337:     function settlePaymentBatch(
338:         RentalOrder[] calldata orders
339:     ) external onlyByProxy permissioned {
340:         
341:         for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND
342:             
343:             _settlePayment(
344:                 orders[i].items,
345:                 orders[i].orderType,
346:                 orders[i].lender,
347:                 orders[i].renter,
348:                 orders[i].startTimestamp,
349:                 orders[i].endTimestamp
350:             );
351:         }
352:     }

```


*GitHub* : [341](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L341-L341)

```solidity
189:     function addRentals(
190:         bytes32 orderHash,
191:         RentalAssetUpdate[] memory rentalAssetUpdates
192:     ) external onlyByProxy permissioned {
193:         
194:         orders[orderHash] = true;
195: 
196:         
197:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) { // <= FOUND
198:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
199: 
200:             
201:             rentedAssets[asset.rentalId] += asset.amount;
202:         }
203:     }

```


*GitHub* : [197](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L197-L197)

```solidity
216:     function removeRentals(
217:         bytes32 orderHash,
218:         RentalAssetUpdate[] calldata rentalAssetUpdates
219:     ) external onlyByProxy permissioned {
220:         
221:         if (!orders[orderHash]) {
222:             revert Errors.StorageModule_OrderDoesNotExist(orderHash);
223:         } else {
224:             
225:             delete orders[orderHash];
226:         }
227: 
228:         
229:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) { // <= FOUND
230:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
231: 
232:             
233:             rentedAssets[asset.rentalId] -= asset.amount;
234:         }
235:     }

```


*GitHub* : [229](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L229-L229)

```solidity
244:     function removeRentalsBatch(
245:         bytes32[] calldata orderHashes,
246:         RentalAssetUpdate[] calldata rentalAssetUpdates
247:     ) external onlyByProxy permissioned {
248:         
249:         for (uint256 i = 0; i < orderHashes.length; ++i) { // <= FOUND
250:             
251:             if (!orders[orderHashes[i]]) {
252:                 revert Errors.StorageModule_OrderDoesNotExist(orderHashes[i]);
253:             } else {
254:                 
255:                 delete orders[orderHashes[i]];
256:             }
257:         }
258: 
259:         
260:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) { // <= FOUND
261:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
262: 
263:             
264:             rentedAssets[asset.rentalId] -= asset.amount;
265:         }
266:     }

```


*GitHub* : [249](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L249-L260)

```solidity
96:     function _convertToStatic(
97:         bytes memory rentalAssetUpdates
98:     ) internal pure returns (RentalAssetUpdate[] memory updates) {
99:         
100:         bytes32 rentalAssetUpdatePointer;
101: 
102:         
103:         uint256 rentalAssetUpdateLength;
104:         assembly {
105:             
106:             
107:             
108:             
109:             rentalAssetUpdatePointer := add(0x20, rentalAssetUpdates)
110: 
111:             
112:             rentalAssetUpdateLength := mload(rentalAssetUpdatePointer)
113:         }
114: 
115:         
116:         updates = new RentalAssetUpdate[](rentalAssetUpdateLength);
117: 
118:         
119:         
120:         for (uint256 i = 0; i < rentalAssetUpdateLength; ++i) { // <= FOUND
121:             
122:             RentalId rentalId;
123:             uint256 amount;
124: 
125:             
126:             assembly {
127:                 
128:                 
129:                 
130:                 
131:                 let currentElementOffset := add(0x20, mul(i, 0x40))
132: 
133:                 
134:                 rentalId := mload(add(rentalAssetUpdatePointer, currentElementOffset))
135: 
136:                 
137:                 amount := mload(
138:                     add(0x20, add(rentalAssetUpdatePointer, currentElementOffset))
139:                 )
140:             }
141: 
142:             
143:             updates[i] = RentalAssetUpdate(rentalId, amount);
144:         }
145:     }

```


*GitHub* : [120](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L120-L120)

```solidity
71:     function reclaimRentalOrder(RentalOrder calldata rentalOrder) external {
72:         
73:         if (address(this) == original) {
74:             revert Errors.ReclaimerPackage_OnlyDelegateCallAllowed();
75:         }
76: 
77:         
78:         
79:         
80:         if (address(this) != rentalOrder.rentalWallet) {
81:             revert Errors.ReclaimerPackage_OnlyRentalSafeAllowed(
82:                 rentalOrder.rentalWallet
83:             );
84:         }
85: 
86:         
87:         uint256 itemCount = rentalOrder.items.length;
88: 
89:         
90:         for (uint256 i = 0; i < itemCount; ++i) { // <= FOUND
91:             Item memory item = rentalOrder.items[i];
92: 
93:             
94:             if (item.itemType == ItemType.ERC721)
95:                 _transferERC721(item, rentalOrder.lender);
96: 
97:             
98:             if (item.itemType == ItemType.ERC1155)
99:                 _transferERC1155(item, rentalOrder.lender);
100:         }
101:     }

```


*GitHub* : [90](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L90-L90)

```solidity
162:     function _deriveRentalOrderHash(
163:         RentalOrder memory order
164:     ) internal view returns (bytes32) {
165:         
166:         bytes32[] memory itemHashes = new bytes32[](order.items.length);
167:         bytes32[] memory hookHashes = new bytes32[](order.hooks.length);
168: 
169:         
170:         for (uint256 i = 0; i < order.items.length; ++i) { // <= FOUND
171:             
172:             itemHashes[i] = _deriveItemHash(order.items[i]);
173:         }
174: 
175:         
176:         for (uint256 i = 0; i < order.hooks.length; ++i) { // <= FOUND
177:             
178:             hookHashes[i] = _deriveHookHash(order.hooks[i]);
179:         }
180: 
181:         return
182:             keccak256(
183:                 abi.encode(
184:                     _RENTAL_ORDER_TYPEHASH,
185:                     order.seaportOrderHash,
186:                     keccak256(abi.encodePacked(itemHashes)),
187:                     keccak256(abi.encodePacked(hookHashes)),
188:                     order.orderType,
189:                     order.lender,
190:                     order.renter,
191:                     order.startTimestamp,
192:                     order.endTimestamp
193:                 )
194:             );
195:     }

```


*GitHub* : [170](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L170-L176)

```solidity
218:     function _deriveOrderMetadataHash(
219:         OrderMetadata memory metadata
220:     ) internal view returns (bytes32) {
221:         
222:         bytes32[] memory hookHashes = new bytes32[](metadata.hooks.length);
223: 
224:         
225:         for (uint256 i = 0; i < metadata.hooks.length; ++i) { // <= FOUND
226:             
227:             hookHashes[i] = _deriveHookHash(metadata.hooks[i]);
228:         }
229: 
230:         
231:         return
232:             keccak256(
233:                 abi.encode(
234:                     _ORDER_METADATA_TYPEHASH,
235:                     metadata.rentDuration,
236:                     keccak256(abi.encodePacked(hookHashes))
237:                 )
238:             );
239:     }

```


*GitHub* : [225](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L225-L225)

```solidity
195:     function _processBaseOrderOffer(
196:         Item[] memory rentalItems,
197:         SpentItem[] memory offers,
198:         uint256 startIndex
199:     ) internal pure {
200:         
201:         if (offers.length == 0) {
202:             revert Errors.CreatePolicy_OfferCountZero();
203:         }
204: 
205:         
206:         ItemType itemType;
207: 
208:         
209:         for (uint256 i; i < offers.length; ++i) { // <= FOUND
210:             
211:             SpentItem memory offer = offers[i];
212: 
213:             
214:             if (offer.isERC721()) {
215:                 itemType = ItemType.ERC721;
216:             }
217:             
218:             else if (offer.isERC1155()) {
219:                 itemType = ItemType.ERC1155;
220:             }
221:             
222:             else {
223:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(offer.itemType);
224:             }
225: 
226:             
227:             
228:             rentalItems[i + startIndex] = Item({
229:                 itemType: itemType,
230:                 settleTo: SettleTo.LENDER,
231:                 token: offer.token,
232:                 amount: offer.amount,
233:                 identifier: offer.identifier
234:             });
235:         }
236:     }

```


*GitHub* : [209](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L209-L209)

```solidity
247:     function _processPayOrderOffer(
248:         Item[] memory rentalItems,
249:         SpentItem[] memory offers,
250:         uint256 startIndex
251:     ) internal pure {
252:         
253:         uint256 totalRentals;
254:         uint256 totalPayments;
255: 
256:         
257:         ItemType itemType;
258:         SettleTo settleTo;
259: 
260:         
261:         for (uint256 i; i < offers.length; ++i) { // <= FOUND
262:             
263:             SpentItem memory offer = offers[i];
264: 
265:             
266:             if (offer.isERC721()) {
267:                 
268:                 
269:                 itemType = ItemType.ERC721;
270:                 settleTo = SettleTo.LENDER;
271: 
272:                 
273:                 totalRentals++; // <= FOUND
274:             }
275:             
276:             else if (offer.isERC1155()) {
277:                 
278:                 
279:                 itemType = ItemType.ERC1155;
280:                 settleTo = SettleTo.LENDER;
281: 
282:                 
283:                 totalRentals++; // <= FOUND
284:             }
285:             
286:             else if (offer.isERC20()) {
287:                 
288:                 
289:                 itemType = ItemType.ERC20;
290:                 settleTo = SettleTo.RENTER;
291: 
292:                 
293:                 totalPayments++; // <= FOUND
294:             }
295:             
296:             else {
297:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(offer.itemType);
298:             }
299: 
300:             
301:             rentalItems[i + startIndex] = Item({
302:                 itemType: itemType,
303:                 settleTo: settleTo,
304:                 token: offer.token,
305:                 amount: offer.amount,
306:                 identifier: offer.identifier
307:             });
308:         }
309: 
310:         
311:         if (totalRentals == 0 || totalPayments == 0) {
312:             revert Errors.CreatePolicy_ItemCountZero(totalRentals, totalPayments);
313:         }
314:     }

```


*GitHub* : [261](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L261-L293)

```solidity
326:     function _processBaseOrderConsideration(
327:         Item[] memory rentalItems,
328:         ReceivedItem[] memory considerations,
329:         uint256 startIndex
330:     ) internal pure {
331:         
332:         if (considerations.length == 0) {
333:             revert Errors.CreatePolicy_ConsiderationCountZero();
334:         }
335: 
336:         
337:         for (uint256 i; i < considerations.length; ++i) { // <= FOUND
338:             
339:             ReceivedItem memory consideration = considerations[i];
340: 
341:             
342:             if (!consideration.isERC20()) {
343:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
344:                     consideration.itemType
345:                 );
346:             }
347: 
348:             
349:             
350:             rentalItems[i + startIndex] = Item({
351:                 itemType: ItemType.ERC20,
352:                 settleTo: SettleTo.LENDER,
353:                 token: consideration.token,
354:                 amount: consideration.amount,
355:                 identifier: consideration.identifier
356:             });
357:         }
358:     }

```


*GitHub* : [337](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L337-L337)

```solidity
367:     function _processPayeeOrderConsideration(
368:         ReceivedItem[] memory considerations
369:     ) internal pure {
370:         
371:         uint256 totalRentals;
372:         uint256 totalPayments;
373: 
374:         
375:         for (uint256 i; i < considerations.length; ++i) { // <= FOUND
376:             
377:             ReceivedItem memory consideration = considerations[i];
378: 
379:             
380:             if (consideration.isERC20()) {
381:                 totalPayments++; // <= FOUND
382:             }
383:             
384:             else if (consideration.isRental()) {
385:                 totalRentals++; // <= FOUND
386:             }
387:             
388:             else {
389:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
390:                     consideration.itemType
391:                 );
392:             }
393:         }
394: 
395:         
396:         if (totalRentals == 0 || totalPayments == 0) {
397:             revert Errors.CreatePolicy_ItemCountZero(totalRentals, totalPayments);
398:         }
399:     }

```


*GitHub* : [375](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L375-L385)

```solidity
464:     function _addHooks(
465:         Hook[] memory hooks,
466:         SpentItem[] memory offerItems,
467:         address rentalWallet
468:     ) internal {
469:         
470:         address target;
471:         uint256 itemIndex;
472:         SpentItem memory offer;
473: 
474:         
475:         for (uint256 i = 0; i < hooks.length; ++i) { // <= FOUND
476:             
477:             target = hooks[i].target;
478: 
479:             
480:             if (!STORE.hookOnStart(target)) {
481:                 revert Errors.Shared_DisabledHook(target);
482:             }
483: 
484:             
485:             itemIndex = hooks[i].itemIndex;
486: 
487:             
488:             offer = offerItems[itemIndex];
489: 
490:             
491:             if (!offer.isRental()) {
492:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
493:             }
494: 
495:             
496:             try
497:                 IHook(target).onStart(
498:                     rentalWallet,
499:                     offer.token,
500:                     offer.identifier,
501:                     offer.amount,
502:                     hooks[i].extraData
503:                 )
504:             {} catch Error(string memory revertReason) {
505:                 
506:                 revert Errors.Shared_HookFailString(revertReason);
507:             } catch Panic(uint256 errorCode) {
508:                 
509:                 string memory stringErrorCode = LibString.toString(errorCode);
510: 
511:                 
512:                 revert Errors.Shared_HookFailString(
513:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
514:                 );
515:             } catch (bytes memory revertData) {
516:                 
517:                 revert Errors.Shared_HookFailBytes(revertData);
518:             }
519:         }
520:     }

```


*GitHub* : [475](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L475-L475)

```solidity
530:     function _rentFromZone(
531:         RentPayload memory payload,
532:         SeaportPayload memory seaportPayload
533:     ) internal {
534:         
535:         _isValidOrderMetadata(payload.metadata, seaportPayload.zoneHash);
536: 
537:         
538:         _isValidSafeOwner(seaportPayload.fulfiller, payload.fulfillment.recipient);
539: 
540:         
541:         _executionInvariantChecks(
542:             seaportPayload.totalExecutions,
543:             payload.fulfillment.recipient
544:         );
545: 
546:         
547:         
548:         Item[] memory items = _convertToItems(
549:             seaportPayload.offer,
550:             seaportPayload.consideration,
551:             payload.metadata.orderType
552:         );
553: 
554:         
555:         
556:         if (
557:             payload.metadata.orderType.isBaseOrder() ||
558:             payload.metadata.orderType.isPayOrder()
559:         ) {
560:             
561:             
562:             
563:             bytes memory rentalAssetUpdates = new bytes(0);
564: 
565:             
566:             
567:             for (uint256 i; i < items.length; ++i) { // <= FOUND
568:                 if (items[i].isRental()) {
569:                     
570:                     _insert(
571:                         rentalAssetUpdates,
572:                         items[i].toRentalId(payload.fulfillment.recipient),
573:                         items[i].amount
574:                     );
575:                 }
576:             }
577: 
578:             
579:             RentalOrder memory order = RentalOrder({
580:                 seaportOrderHash: seaportPayload.orderHash,
581:                 items: items,
582:                 hooks: payload.metadata.hooks,
583:                 orderType: payload.metadata.orderType,
584:                 lender: seaportPayload.offerer,
585:                 renter: payload.intendedFulfiller,
586:                 rentalWallet: payload.fulfillment.recipient,
587:                 startTimestamp: block.timestamp,
588:                 endTimestamp: block.timestamp + payload.metadata.rentDuration
589:             });
590: 
591:             
592:             bytes32 orderHash = _deriveRentalOrderHash(order);
593: 
594:             
595:             STORE.addRentals(orderHash, _convertToStatic(rentalAssetUpdates));
596: 
597:             
598:             
599:             for (uint256 i = 0; i < items.length; ++i) { // <= FOUND
600:                 if (items[i].isERC20()) {
601:                     ESCRW.increaseDeposit(items[i].token, items[i].amount);
602:                 }
603:             }
604: 
605:             
606:             if (payload.metadata.hooks.length > 0) {
607:                 _addHooks(
608:                     payload.metadata.hooks,
609:                     seaportPayload.offer,
610:                     payload.fulfillment.recipient
611:                 );
612:             }
613: 
614:             
615:             _emitRentalOrderStarted(order, orderHash, payload.metadata.emittedExtraData);
616:         }
617:     }

```


*GitHub* : [567](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L567-L599)

```solidity
691:     function _executionInvariantChecks(
692:         ReceivedItem[] memory executions,
693:         address expectedRentalSafe
694:     ) internal view {
695:         for (uint256 i = 0; i < executions.length; ++i) { // <= FOUND
696:             ReceivedItem memory execution = executions[i];
697: 
698:             
699:             if (execution.isERC20()) {
700:                 _checkExpectedRecipient(execution, address(ESCRW));
701:             }
702:             
703:             
704:             else if (execution.isRental()) {
705:                 _checkExpectedRecipient(execution, expectedRentalSafe);
706:             }
707:             
708:             else {
709:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
710:                     execution.itemType
711:                 );
712:             }
713:         }
714:     }

```


*GitHub* : [695](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L695-L695)

```solidity
194:     function _removeHooks(
195:         Hook[] calldata hooks,
196:         Item[] calldata rentalItems,
197:         address rentalWallet
198:     ) internal {
199:         
200:         address target;
201:         uint256 itemIndex;
202:         Item memory item;
203: 
204:         
205:         for (uint256 i = 0; i < hooks.length; ++i) { // <= FOUND
206:             
207:             target = hooks[i].target;
208: 
209:             
210:             if (!STORE.hookOnStop(target)) {
211:                 revert Errors.Shared_DisabledHook(target);
212:             }
213: 
214:             
215:             itemIndex = hooks[i].itemIndex;
216: 
217:             
218:             item = rentalItems[itemIndex];
219: 
220:             
221:             if (!item.isRental()) {
222:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
223:             }
224: 
225:             
226:             try
227:                 IHook(target).onStop(
228:                     rentalWallet,
229:                     item.token,
230:                     item.identifier,
231:                     item.amount,
232:                     hooks[i].extraData
233:                 )
234:             {} catch Error(string memory revertReason) {
235:                 
236:                 revert Errors.Shared_HookFailString(revertReason);
237:             } catch Panic(uint256 errorCode) {
238:                 
239:                 string memory stringErrorCode = LibString.toString(errorCode);
240: 
241:                 
242:                 revert Errors.Shared_HookFailString(
243:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
244:                 );
245:             } catch (bytes memory revertData) {
246:                 
247:                 revert Errors.Shared_HookFailBytes(revertData);
248:             }
249:         }
250:     }

```


*GitHub* : [205](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L205-L205)

```solidity
265:     function stopRent(RentalOrder calldata order) external {
266:         
267:         _validateRentalCanBeStoped(order.orderType, order.endTimestamp, order.lender);
268: 
269:         
270:         
271:         
272:         bytes memory rentalAssetUpdates = new bytes(0);
273: 
274:         
275:         
276:         for (uint256 i; i < order.items.length; ++i) { // <= FOUND
277:             if (order.items[i].isRental()) {
278:                 
279:                 _insert(
280:                     rentalAssetUpdates,
281:                     order.items[i].toRentalId(order.rentalWallet),
282:                     order.items[i].amount
283:                 );
284:             }
285:         }
286: 
287:         
288:         if (order.hooks.length > 0) {
289:             _removeHooks(order.hooks, order.items, order.rentalWallet);
290:         }
291: 
292:         
293:         _reclaimRentedItems(order);
294: 
295:         
296:         ESCRW.settlePayment(order);
297: 
298:         
299:         STORE.removeRentals(
300:             _deriveRentalOrderHash(order),
301:             _convertToStatic(rentalAssetUpdates)
302:         );
303: 
304:         
305:         _emitRentalOrderStopped(order.seaportOrderHash, msg.sender);
306:     }

```


*GitHub* : [276](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L276-L276)

```solidity
313:     function stopRentBatch(RentalOrder[] calldata orders) external {
314:         
315:         bytes32[] memory orderHashes = new bytes32[](orders.length);
316: 
317:         
318:         
319:         
320:         bytes memory rentalAssetUpdates = new bytes(0);
321: 
322:         
323:         
324:         for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND
325:             
326:             _validateRentalCanBeStoped(
327:                 orders[i].orderType,
328:                 orders[i].endTimestamp,
329:                 orders[i].lender
330:             );
331: 
332:             
333:             for (uint256 j = 0; j < orders[i].items.length; ++j) { // <= FOUND
334:                 
335:                 if (orders[i].items[j].isRental()) {
336:                     _insert(
337:                         rentalAssetUpdates,
338:                         orders[i].items[j].toRentalId(orders[i].rentalWallet),
339:                         orders[i].items[j].amount
340:                     );
341:                 }
342:             }
343: 
344:             
345:             orderHashes[i] = _deriveRentalOrderHash(orders[i]);
346: 
347:             
348:             if (orders[i].hooks.length > 0) {
349:                 _removeHooks(orders[i].hooks, orders[i].items, orders[i].rentalWallet);
350:             }
351: 
352:             
353:             _reclaimRentedItems(orders[i]);
354: 
355:             
356:             _emitRentalOrderStopped(orderHashes[i], msg.sender);
357:         }
358: 
359:         
360:         ESCRW.settlePaymentBatch(orders);
361: 
362:         
363:         STORE.removeRentalsBatch(orderHashes, _convertToStatic(rentalAssetUpdates));
364:     }

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L324-L333)

```solidity
418:     function _activatePolicy(Policy policy_) internal {
419:         
420:         if (policy_.isActive())
421:             revert Errors.Kernel_PolicyAlreadyApproved(address(policy_));
422: 
423:         
424:         Permissions[] memory requests = policy_.requestPermissions();
425:         _setPolicyPermissions(policy_, requests, true);
426: 
427:         
428:         activePolicies.push(policy_);
429: 
430:         
431:         getPolicyIndex[policy_] = activePolicies.length - 1;
432: 
433:         
434:         Keycode[] memory dependencies = policy_.configureDependencies();
435:         uint256 depLength = dependencies.length;
436: 
437:         
438:         for (uint256 i; i < depLength; ++i) { // <= FOUND
439:             Keycode keycode = dependencies[i];
440: 
441:             
442:             moduleDependents[keycode].push(policy_);
443: 
444:             
445:             getDependentIndex[keycode][policy_] = moduleDependents[keycode].length - 1;
446:         }
447: 
448:         
449:         policy_.setActiveStatus(true);
450:     }

```


*GitHub* : [438](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L438-L438)

```solidity
508:     function _migrateKernel(Kernel newKernel_) internal {
509:         uint256 keycodeLen = allKeycodes.length;
510: 
511:         
512:         for (uint256 i; i < keycodeLen; ++i) { // <= FOUND
513:             
514:             Module module = Module(getModuleForKeycode[allKeycodes[i]]);
515:             
516:             module.changeKernel(newKernel_);
517:         }
518: 
519:         
520:         uint256 policiesLen = activePolicies.length;
521:         for (uint256 j; j < policiesLen; ++j) { // <= FOUND
522:             
523:             Policy policy = activePolicies[j];
524: 
525:             
526:             policy.setActiveStatus(false);
527: 
528:             
529:             policy.changeKernel(newKernel_);
530:         }
531:     }

```


*GitHub* : [512](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L512-L521)

```solidity
540:     function _reconfigurePolicies(Keycode keycode_) internal {
541:         
542:         Policy[] memory dependents = moduleDependents[keycode_];
543:         uint256 depLength = dependents.length;
544: 
545:         
546:         for (uint256 i; i < depLength; ++i) { // <= FOUND
547:             
548:             dependents[i].configureDependencies();
549:         }
550:     }

```


*GitHub* : [546](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L546-L546)

```solidity
560:     function _setPolicyPermissions(
561:         Policy policy_,
562:         Permissions[] memory requests_,
563:         bool grant_
564:     ) internal {
565:         uint256 reqLength = requests_.length;
566:         for (uint256 i = 0; i < reqLength; ++i) { // <= FOUND
567:             
568:             Permissions memory request = requests_[i];
569:             modulePermissions[request.keycode][policy_][request.funcSelector] = grant_;
570: 
571:             emit Events.PermissionsUpdated(
572:                 request.keycode,
573:                 policy_,
574:                 request.funcSelector,
575:                 grant_
576:             );
577:         }
578:     }

```


*GitHub* : [566](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L566-L566)

```solidity
586:     function _pruneFromDependents(Policy policy_) internal {
587:         
588:         Keycode[] memory dependencies = policy_.configureDependencies();
589:         uint256 depcLength = dependencies.length;
590: 
591:         
592:         for (uint256 i; i < depcLength; ++i) { // <= FOUND
593:             
594:             Keycode keycode = dependencies[i];
595:             Policy[] storage dependents = moduleDependents[keycode];
596: 
597:             
598:             uint256 origIndex = getDependentIndex[keycode][policy_];
599: 
600:             
601:             Policy lastPolicy = dependents[dependents.length - 1];
602: 
603:             
604:             dependents[origIndex] = lastPolicy;
605: 
606:             
607:             
608:             dependents.pop();
609: 
610:             
611:             getDependentIndex[keycode][lastPolicy] = origIndex;
612: 
613:             
614:             delete getDependentIndex[keycode][policy_];
615:         }
616:     }

```


*GitHub* : [592](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L592-L592)
### [G-14]<a name="g-14"></a> Use byte32 in place of string
For strings of 32 char strings and below you can use bytes32 instead as it's more gas efficient

*There are 5 instance(s) of this issue:*

```solidity
25: 
27:     string internal constant _NAME = "ReNFT-Rentals"; // <= FOUND

```


*GitHub* : [25](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L25-L27)

```solidity
26:     string internal constant _VERSION = "1.0.0"; // <= FOUND

```


*GitHub* : [26](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L26-L26)

```solidity
315: 
316:         
317:         eip712DomainTypehash = keccak256(
318:             abi.encodePacked(
319:                 "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)" // <= FOUND
320:             )
321:         );

```


*GitHub* : [315](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L315-L319)

```solidity
512: 
513:                 
514:                 revert Errors.Shared_HookFailString(
515:                     string.concat("Hook reverted: Panic code ", stringErrorCode) // <= FOUND
516:                 );

```


*GitHub* : [512](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L512-L515)

```solidity
512: 
513:             
514:             revert Errors.Shared_HookFailString(
515:                 string.concat("Hook reverted: Panic code ", stringErrorCode) // <= FOUND
516:             );

```


*GitHub* : [512](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L512-L515)
### [G-15]<a name="g-15"></a> Default bool values are manually reset
Using .delete is better than resetting a Solidity variable to its default value manually because it frees up storage space on the Ethereum blockchain, resulting in gas cost savings.

*There are 1 instance(s) of this issue:*

```solidity
333:     function revokeRole(Role role_, address addr_) public onlyAdmin { // <= FOUND
334:         
335:         if (!isRole[role_]) revert Errors.Kernel_RoleDoesNotExist(role_);
336: 
337:         
338:         if (!hasRole[addr_][role_])
339:             revert Errors.Kernel_AddressDoesNotHaveRole(addr_, role_);
340: 
341:         
342:         hasRole[addr_][role_] = false;
343: 
344:         emit Events.RoleRevoked(role_, addr_);
345:     }

```


*GitHub* : [333](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L333-L333)
### [G-16]<a name="g-16"></a> Default int values are manually reset
Using .delete is better than resetting a Solidity variable to its default value manually because it frees up storage space on the Ethereum blockchain, resulting in gas cost savings.

*There are 1 instance(s) of this issue:*

```solidity
19: 
21:     bytes1 constant create2_ff = 0xff; // <= FOUND

```


*GitHub* : [19](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L19-L21)
### [G-17]<a name="g-17"></a> <= or >= is more efficient than < or > 
Make such found comparisons to the <=/>= equivalent when comparing against integer literals

*There are 2 instance(s) of this issue:*

```solidity
329: 
330:         
331:         if (data.length < 4) { // <= FOUND

```


*GitHub* : [331](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L331-L331)

```solidity
382:         
383:         if (feeNumerator > 10000) { // <= FOUND

```


*GitHub* : [383](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L383-L383)
### [G-18]<a name="g-18"></a> Use assembly to check for the zero address

Using assembly for address comparisons in Solidity can save gas because it allows for more direct access to the Ethereum Virtual Machine (EVM), reducing the overhead of higher-level operations. Solidity's high-level abstraction simplifies coding but can introduce additional gas costs. Using assembly for simple operations like address comparisons can be more gas-efficient.

*There are 4 instance(s) of this issue:*

```solidity
309:     function checkTransaction(
310:         address to,
311:         uint256 value,
312:         bytes memory data,
313:         Enum.Operation operation,
314:         uint256,
315:         uint256,
316:         uint256,
317:         address,
318:         address payable,
319:         bytes memory,
320:         address
321:     ) external override {
322:         
323:         
324:         if (operation == Enum.Operation.DelegateCall && !STORE.whitelistedDelegates(to)) {
325:             revert Errors.GuardPolicy_UnauthorizedDelegateCall(to);
326:         }
327: 
328:         
329:         if (data.length < 4) {
330:             revert Errors.GuardPolicy_FunctionSelectorRequired();
331:         }
332: 
333:         
334:         address hook = STORE.contractToHook(to);
335:         bool isActive = STORE.hookOnTransaction(hook);
336: 
337:         
338:         if (hook != address(0) && isActive) { // <= FOUND
339:             _forwardToHook(hook, msg.sender, to, value, data);
340:         }
341:         
342:         else {
343:             _checkTransaction(msg.sender, to, data);
344:         }
345:     }

```


*GitHub* : [309](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L309-L338)

```solidity
180:     function getModuleAddress(Keycode keycode_) internal view returns (address) {
181:         address moduleForKeycode = address(kernel.getModuleForKeycode(keycode_));
182:         if (moduleForKeycode == address(0)) // <= FOUND
183:             revert Errors.Policy_ModuleDoesNotExist(keycode_);
184:         return moduleForKeycode;
185:     }

```


*GitHub* : [180](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L180-L182)

```solidity
356:     function _installModule(Module newModule_) internal {
357:         
358:         Keycode keycode = newModule_.KEYCODE();
359: 
360:         
361:         if (address(getModuleForKeycode[keycode]) != address(0)) { // <= FOUND
362:             revert Errors.Kernel_ModuleAlreadyInstalled(keycode);
363:         }
364: 
365:         
366:         getModuleForKeycode[keycode] = newModule_;
367: 
368:         
369:         getKeycodeForModule[newModule_] = keycode;
370: 
371:         
372:         allKeycodes.push(keycode);
373: 
374:         
375:         newModule_.INIT();
376:     }

```


*GitHub* : [356](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L356-L361)

```solidity
383:     function _upgradeModule(Module newModule_) internal {
384:         
385:         Keycode keycode = newModule_.KEYCODE();
386: 
387:         
388:         Module oldModule = getModuleForKeycode[keycode];
389: 
390:         
391:         
392:         if (address(oldModule) == address(0) || oldModule == newModule_) { // <= FOUND
393:             revert Errors.Kernel_InvalidModuleUpgrade(keycode);
394:         }
395: 
396:         
397:         getKeycodeForModule[oldModule] = Keycode.wrap(bytes5(0));
398: 
399:         
400:         getKeycodeForModule[newModule_] = keycode;
401: 
402:         
403:         getModuleForKeycode[keycode] = newModule_;
404: 
405:         
406:         newModule_.INIT();
407: 
408:         
409:         
410:         _reconfigurePolicies(keycode);
411:     }

```


*GitHub* : [383](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L383-L392)
### [G-19]<a name="g-19"></a> Divisions which do not divide by -X cannot overflow or overflow so such operations can be unchecked to save gas
Make such found divisions are unchecked when ensured it is safe to do so

*There are 2 instance(s) of this issue:*

```solidity
88:     function _calculateFee(uint256 amount) internal view returns (uint256) {
89:         
90:         return (amount * fee) / 10000; // <= FOUND
91:     }

```


*GitHub* : [90](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L90-L90)

```solidity
132:     function _calculatePaymentProRata(
133:         uint256 amount,
134:         uint256 elapsedTime,
135:         uint256 totalTime
136:     ) internal pure returns (uint256 renterAmount, uint256 lenderAmount) {
137:         
138:         uint256 numerator = (amount * elapsedTime) * 1000;
139: 
140:         
141:         
142:         renterAmount = ((numerator / totalTime) + 500) / 1000; // <= FOUND
143: 
144:         
145:         lenderAmount = amount - renterAmount;
146:     }

```


*GitHub* : [142](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L142-L142)
### [G-20]<a name="g-20"></a> Consider activating via-ir for deploying
The Solidity compiler's Intermediate Representation (IR) based code generator, which can be activated using --via-ir on the command line or {"viaIR": true} in the options, serves a dual purpose. Firstly, it boosts the transparency and audibility of code generation, which enhances developers' comprehension and control over the contract's final bytecode. Secondly, it enables more sophisticated optimization passes that span multiple functions, thereby potentially leading to more efficient bytecode.

It's important to note that using the IR-based code generator may lengthen compile times due to the extra optimization steps. Therefore, it's advised to test your contract with and without this option enabled to measure the performance and gas cost implications. If the IR-based code generator significantly enhances your contract's performance or reduces gas costs, consider using the --via-ir flag during deployment. This way, you can leverage more advanced compiler optimizations without hindering your development workflow.

*There are 1 instance(s) of this issue:*

```solidity
24: all

```


*GitHub* : [24](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L24-L24)
### [G-21]<a name="g-21"></a> Expression ("") is cheaper than new bytes(0)
In Solidity, using an empty string ("") instead of "new bytes(0)" in expressions can result in cheaper gas costs. This is because "new bytes(0)" creates a dynamic byte array, leading to additional overhead. By simply using ("") when an empty bytes array is needed, you can optimize for gas efficiency.

*There are 2 instance(s) of this issue:*

```solidity
563:             
564:             
565:             
566:             bytes memory rentalAssetUpdates = new bytes(0); // <= FOUND

```


*GitHub* : [566](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L566-L566)

```solidity
563: 
564:         
565:         
566:         
567:         bytes memory rentalAssetUpdates = new bytes(0); // <= FOUND

```


*GitHub* : [567](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L567-L567)
### [G-22]<a name="g-22"></a> Add unchecked {} for subtractions where the operands cannot underflow
n Solidity 0.8.x and above, arithmetic operations like subtraction automatically check for underflows and overflows, and revert the transaction if such a condition is met. This built-in safety feature provides a layer of security against potential numerical errors. However, these automatic checks also come with additional gas costs.

In some situations, you may already have a guard condition, like a require() statement or an if statement, that ensures the safety of the arithmetic operation. In such cases, the automatic check becomes redundant and leads to unnecessary gas expenditure.

For example, you may have a function that subtracts a smaller number from a larger one, and you may have already verified that the smaller number is indeed smaller. In this case, you're already sure that the subtraction operation won't underflow, so there's no need for the automatic check.

In these situations, you can use the unchecked { } block around the subtraction operation to skip the automatic check. This will reduce gas costs and make your contract more efficient, without sacrificing security. However, it's critical to use unchecked { } only when you're absolutely sure that the operation is safe.

*There are 8 instance(s) of this issue:*

```solidity
145: 
146:         
147:         lenderAmount = amount - renterAmount; // <= FOUND

```


*GitHub* : [145](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L145-L147)

```solidity
224:         
225:         uint256 elapsedTime = block.timestamp - start; // <= FOUND

```


*GitHub* : [224](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L224-L225)

```solidity
225:         uint256 totalTime = end - start; // <= FOUND

```


*GitHub* : [225](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L225-L225)

```solidity
405: 
406:         
407:         uint256 skimmedBalance = trueBalance - syncedBalance; // <= FOUND

```


*GitHub* : [405](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L405-L407)

```solidity
431: 
432:         
433:         getPolicyIndex[policy_] = activePolicies.length - 1; // <= FOUND

```


*GitHub* : [431](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L431-L433)

```solidity
445: 
446:             
447:             getDependentIndex[keycode][policy_] = moduleDependents[keycode].length - 1; // <= FOUND

```


*GitHub* : [445](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L445-L447)

```solidity
469: 
470:         
471:         Policy lastPolicy = activePolicies[activePolicies.length - 1]; // <= FOUND

```


*GitHub* : [469](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L469-L471)

```solidity
601: 
602:             
603:             Policy lastPolicy = dependents[dependents.length - 1]; // <= FOUND

```


*GitHub* : [601](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L601-L603)
### [G-23]<a name="g-23"></a> Private functions used once can be inlined
Private functions which are only called once can be inlined to save GAS.

*There are 4 instance(s) of this issue:*

```solidity
32:     function _transferERC721(Item memory item, address recipient) private  // <= FOUND

```


*GitHub* : [32](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L32-L32)

```solidity
42:     function _transferERC1155(Item memory item, address recipient) private  // <= FOUND

```


*GitHub* : [42](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L42-L42)

```solidity
159:     function _forwardToHook( // <= FOUND
160:         address hook,
161:         address safe,
162:         address to,
163:         uint256 value,
164:         bytes memory data
165:     ) private 

```


*GitHub* : [159](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L159-L159)

```solidity
195:     function _checkTransaction(address from, address to, bytes memory data) private view  // <= FOUND

```


*GitHub* : [195](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L195-L195)
### [G-24]<a name="g-24"></a> Use bitmap to save gas
Bitmaps in Solidity are essentially a way of representing a set of boolean values within an integer type variable such as `uint256`. Each bit in the integer represents a true or false value (1 or 0), thus allowing efficient storage of multiple boolean values.

Bitmaps can save gas in the Ethereum network because they condense a lot of information into a small amount of storage. In Ethereum, storage is one of the most significant costs in terms of gas usage. By reducing the amount of storage space needed, you can potentially save on gas fees.

Here's a quick comparison:

If you were to represent 256 different boolean values in the traditional way, you would have to declare 256 different `bool` variables. Given that each `bool` occupies a storage slot and each storage slot costs 20,000 gas to initialize, you would end up paying a considerable amount of gas.

On the other hand, if you were to use a bitmap, you could store these 256 boolean values within a single `uint256` variable. In other words, you'd only pay for a single storage slot, resulting in significant gas savings.

However, it's important to note that while bitmaps can provide gas efficiencies, they do add complexity to the code, making it harder to read and maintain. Also, using bitmaps is efficient only when dealing with a large number of boolean variables that are frequently changed or accessed together. 

In contrast, the straightforward counterpart to bitmaps would be using arrays or mappings to store boolean values, with each `bool` value occupying its own storage slot. This approach is simpler and more readable but could potentially be more expensive in terms of gas usage.

*There are 7 instance(s) of this issue:*

```solidity
90:         initialized = true; // <= FOUND

```


*GitHub* : [90](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L90-L90)

```solidity
405: 
406:         
407:         uint256 skimmedBalance = trueBalance - syncedBalance; // <= FOUND

```


*GitHub* : [407](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L407-L407)

```solidity
194:         
195:         orders[orderHash] = true; // <= FOUND

```


*GitHub* : [195](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L195-L195)

```solidity
50: 
51:         
52:         deployed[targetDeploymentAddress] = true; // <= FOUND

```


*GitHub* : [52](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L52-L52)

```solidity
319: 
320:         
321:         if (!isRole[role_]) isRole[role_] = true; // <= FOUND

```


*GitHub* : [321](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L321-L321)

```solidity
322: 
323:         
324:         hasRole[addr_][role_] = true; // <= FOUND

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L324-L324)

```solidity
342: 
343:         
344:         hasRole[addr_][role_] = false; // <= FOUND

```


*GitHub* : [344](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L344-L344)
### [G-25]<a name="g-25"></a> Use assembly hashing
From a gas standpoint, the assembly version of the keccak256 hashing function can be more efficient than the high-level Solidity version. This is because Solidity has additional overhead when handling function calls and memory management, which can increase the gas cost.

*There are 10 instance(s) of this issue:*

```solidity
309:         
310:         nameHash = keccak256(bytes(_NAME)); // <= FOUND

```


*GitHub* : [309](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L309-L310)

```solidity
312: 
313:         
314:         versionHash = keccak256(bytes(_VERSION)); // <= FOUND

```


*GitHub* : [312](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L312-L314)

```solidity
315: 
316:         
317:         eip712DomainTypehash = keccak256( // <= FOUND
318:             abi.encodePacked(
319:                 "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
320:             )
321:         );

```


*GitHub* : [315](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L315-L317)

```solidity
367: 
368:         
369:         itemTypeHash = keccak256(itemTypeString); // <= FOUND

```


*GitHub* : [367](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L367-L369)

```solidity
370: 
371:         
372:         hookTypeHash = keccak256(hookTypeString); // <= FOUND

```


*GitHub* : [370](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L370-L372)

```solidity
373: 
374:         
375:         rentalOrderTypeHash = keccak256( // <= FOUND
376:             abi.encode(rentalOrderTypeString, hookTypeString, itemTypeString)
377:         );

```


*GitHub* : [373](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L373-L375)

```solidity
394: 
395:             
396:             rentPayloadTypeHash = keccak256( // <= FOUND
397:                 abi.encodePacked(
398:                     rentPayloadTypeString,
399:                     orderMetadataTypeString,
400:                     orderFulfillmentTypeString
401:                 )
402:             );

```


*GitHub* : [394](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L394-L396)

```solidity
403: 
404:             
405:             orderFulfillmentTypeHash = keccak256(orderFulfillmentTypeString); // <= FOUND

```


*GitHub* : [403](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L403-L405)

```solidity
406: 
407:             
408:             orderMetadataTypeHash = keccak256(orderMetadataTypeString); // <= FOUND

```


*GitHub* : [406](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L406-L408)

```solidity
89:         
90:         bytes32 addressHash = keccak256( // <= FOUND
91:             abi.encodePacked(create2_ff, address(this), salt, keccak256(initCode))
92:         );

```


*GitHub* : [89](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L89-L90)
### [G-26]<a name="g-26"></a> Consider using OZ EnumerateSet in place of nested mappings
Nested mappings and multi-dimensional arrays in Solidity operate through a process of double hashing, wherein the original storage slot and the first key are concatenated and hashed, and then this hash is again concatenated with the second key and hashed. This process can be quite gas expensive due to the double-hashing operation and subsequent storage operation (sstore).

A possible optimization involves manually concatenating the keys followed by a single hash operation and an sstore. However, this technique introduces the risk of storage collision, especially when there are other nested hash maps in the contract that use the same key types. Because Solidity is unaware of the number and structure of nested hash maps in a contract, it follows a conservative approach in computing the storage slot to avoid possible collisions.

OpenZeppelin's EnumerableSet provides a potential solution to this problem. It creates a data structure that combines the benefits of set operations with the ability to enumerate stored elements, which is not natively available in Solidity. EnumerableSet handles the element uniqueness internally and can therefore provide a more gas-efficient and collision-resistant alternative to nested mappings or multi-dimensional arrays in certain scenarios.

*There are 3 instance(s) of this issue:*

```solidity
218:     mapping(Keycode => mapping(Policy => uint256)) public getDependentIndex; // <= FOUND

```


*GitHub* : [218](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L218-L218)

```solidity
221:     mapping(Keycode => mapping(Policy => mapping(bytes4 => bool))) // <= FOUND

```


*GitHub* : [221](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L221-L221)

```solidity
229:     mapping(address => mapping(Role => bool)) public hasRole; // <= FOUND

```


*GitHub* : [229](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L229-L229)
### [G-27]<a name="g-27"></a> Use assembly to emit events
With the use of inline assembly in Solidity, we can take advantage of low-level features like scratch space and the free memory pointer, offering more gas-efficient ways of emitting events. The scratch space is a certain area of memory where we can temporarily store data, and the free memory pointer indicates the next available memory slot. Using these, we can efficiently assemble event data without incurring additional memory expansion costs. However, safety is paramount: to avoid overwriting or leakage, we must cache the free memory pointer before use and restore it afterward, ensuring that it points to the correct memory location post-operation.

*There are 8 instance(s) of this issue:*

```solidity
411: 
412:         
413:         emit Events.FeeTaken(token, skimmedBalance); // <= FOUND

```


*GitHub* : [413](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L413-L413)

```solidity
171:         
172:         emit Events.RentalOrderStarted( // <= FOUND
173:             orderHash,
174:             extraData,
175:             order.seaportOrderHash,
176:             order.items,
177:             order.hooks,
178:             order.orderType,
179:             order.lender,
180:             order.renter,
181:             order.rentalWallet,
182:             order.startTimestamp,
183:             order.endTimestamp
184:         );

```


*GitHub* : [172](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L172-L172)

```solidity
192: 
193:         
194:         emit Events.RentalSafeDeployment(safe, owners, threshold); // <= FOUND

```


*GitHub* : [194](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L194-L194)

```solidity
113:         
114:         emit Events.RentalOrderStopped(seaportOrderHash, stopper); // <= FOUND

```


*GitHub* : [114](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L114-L114)

```solidity
301: 
302:         emit Events.ActionExecuted(action_, target_); // <= FOUND

```


*GitHub* : [302](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L302-L302)

```solidity
324: 
325:         emit Events.RoleGranted(role_, addr_); // <= FOUND

```


*GitHub* : [325](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L325-L325)

```solidity
344: 
345:         emit Events.RoleRevoked(role_, addr_); // <= FOUND

```


*GitHub* : [345](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L345-L345)

```solidity
571: 
572:             emit Events.PermissionsUpdated( // <= FOUND
573:                 request.keycode,
574:                 policy_,
575:                 request.funcSelector,
576:                 grant_
577:             );

```


*GitHub* : [572](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L572-L572)
### [G-28]<a name="g-28"></a> Use solady library where possible to save gas
The following OpenZeppelin imports have a Solady equivalent, as such they can be used to save GAS as Solady modules have been specifically designed to be as GAS efficient as possible

*There are 3 instance(s) of this issue:*

```solidity
4: import {IERC721} from "@openzeppelin-contracts/token/ERC721/IERC721.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L4-L4)

```solidity
4: import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L4-L4)

```solidity
5: import {IERC1155} from "@openzeppelin-contracts/token/ERC1155/IERC1155.sol"; // <= FOUND

```


*GitHub* : [5](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L5-L5)
### [G-29]<a name="g-29"></a> Use assembly in place of abi.decode to extract calldata values more efficiently
Using inline assembly to extract calldata values can be more gas-efficient than using `abi.decode` in Solidity. Inline assembly gives more direct access to EVM operations, enabling optimized usage of calldata. However, assembly should be used judiciously as it's more prone to errors. Opt for this approach when performance is critical and the complexity it introduces is manageable.

*There are 2 instance(s) of this issue:*

```solidity
115: 
116:         
117:         
118:         
119:         
120:         
121:         
122:         
123:         
124:         
125:         if (!success || (data.length != 0 && !abi.decode(data, (bool)))) { // <= FOUND

```


*GitHub* : [125](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L125-L125)

```solidity
737:         
738:         (RentPayload memory payload, bytes memory signature) = abi.decode( // <= FOUND
739:             zoneParams.extraData,
740:             (RentPayload, bytes)
741:         );

```


*GitHub* : [738](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L738-L738)
### [G-30]<a name="g-30"></a> Counting down in for statements is more gas efficient
Looping downwards in Solidity is more gas efficient due to how the EVM compares variables. In a 'for' loop that counts down, the end condition is usually to compare with zero, which is cheaper than comparing with another number. As such, restructure your loops to count downwards where possible.

*There are 18 instance(s) of this issue:*

```solidity
231:        for (uint256 i = 0; i < items.length; ++i) { // <= FOUND
232:             
233:             Item memory item = items[i];
234: 
235:             
236:             if (item.isERC20()) {
237:                 
238:                 
239:                 uint256 paymentAmount = item.amount;
240: 
241:                 
242:                 if (fee != 0) {
243:                     
244:                     uint256 paymentFee = _calculateFee(paymentAmount);
245: 
246:                     
247:                     paymentAmount -= paymentFee;
248:                 }
249: 
250:                 
251:                 
252:                 _decreaseDeposit(item.token, item.amount);
253: 
254:                 
255:                 if (orderType.isPayOrder() && !isRentalOver) {
256:                     
257:                     _settlePaymentProRata(
258:                         item.token,
259:                         paymentAmount,
260:                         lender,
261:                         renter,
262:                         elapsedTime,
263:                         totalTime
264:                     );
265:                 }
266:                 
267:                 else if (
268:                     (orderType.isPayOrder() && isRentalOver) || orderType.isBaseOrder()
269:                 ) {
270:                     
271:                     _settlePaymentInFull(
272:                         item.token,
273:                         paymentAmount,
274:                         item.settleTo,
275:                         lender,
276:                         renter
277:                     );
278:                 } else {
279:                     revert Errors.Shared_OrderTypeNotSupported(uint8(orderType));
280:                 }

```


*GitHub* : [231](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L231-L231)

```solidity
341:        for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND
342:             
343:             _settlePayment(
344:                 orders[i].items,
345:                 orders[i].orderType,
346:                 orders[i].lender,
347:                 orders[i].renter,
348:                 orders[i].startTimestamp,
349:                 orders[i].endTimestamp
350:             );
351:         }

```


*GitHub* : [341](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L341-L341)

```solidity
197:        for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) { // <= FOUND
198:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
199: 
200:             
201:             rentedAssets[asset.rentalId] += asset.amount;
202:         }

```


*GitHub* : [197](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L197-L197)

```solidity
249:        for (uint256 i = 0; i < orderHashes.length; ++i) { // <= FOUND
250:             
251:             if (!orders[orderHashes[i]]) {
252:                 revert Errors.StorageModule_OrderDoesNotExist(orderHashes[i]);
253:             } else {
254:                 
255:                 delete orders[orderHashes[i]];
256:             }
257:         }

```


*GitHub* : [249](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L249-L249)

```solidity
170:        for (uint256 i = 0; i < order.items.length; ++i) { // <= FOUND
171:             
172:             itemHashes[i] = _deriveItemHash(order.items[i]);
173:         }

```


*GitHub* : [170](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L170-L170)

```solidity
225:        for (uint256 i = 0; i < metadata.hooks.length; ++i) { // <= FOUND
226:             
227:             hookHashes[i] = _deriveHookHash(metadata.hooks[i]);
228:         }

```


*GitHub* : [225](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L225-L225)

```solidity
261:        for (uint256 i; i < offers.length; ++i) { // <= FOUND
262:             
263:             SpentItem memory offer = offers[i];
264: 
265:             
266:             if (offer.isERC721()) {
267:                 
268:                 
269:                 itemType = ItemType.ERC721;
270:                 settleTo = SettleTo.LENDER;
271: 
272:                 
273:                 totalRentals++; // <= FOUND
274:             }
275:             
276:             else if (offer.isERC1155()) {
277:                 
278:                 
279:                 itemType = ItemType.ERC1155;
280:                 settleTo = SettleTo.LENDER;
281: 
282:                 
283:                 totalRentals++; // <= FOUND
284:             }
285:             
286:             else if (offer.isERC20()) {
287:                 
288:                 
289:                 itemType = ItemType.ERC20;
290:                 settleTo = SettleTo.RENTER;
291: 
292:                 
293:                 totalPayments++; // <= FOUND
294:             }
295:             
296:             else {
297:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(offer.itemType);
298:             }
299: 
300:             
301:             rentalItems[i + startIndex] = Item({
302:                 itemType: itemType,
303:                 settleTo: settleTo,
304:                 token: offer.token,
305:                 amount: offer.amount,
306:                 identifier: offer.identifier
307:             });
308:         }

```


*GitHub* : [261](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L261-L293)

```solidity
375:        for (uint256 i; i < considerations.length; ++i) { // <= FOUND
376:             
377:             ReceivedItem memory consideration = considerations[i];
378: 
379:             
380:             if (consideration.isERC20()) {
381:                 totalPayments++; // <= FOUND
382:             }
383:             
384:             else if (consideration.isRental()) {
385:                 totalRentals++; // <= FOUND
386:             }
387:             
388:             else {
389:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
390:                     consideration.itemType
391:                 );
392:             }
393:         }

```


*GitHub* : [375](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L375-L385)

```solidity
475:        for (uint256 i = 0; i < hooks.length; ++i) { // <= FOUND
476:             
477:             target = hooks[i].target;
478: 
479:             
480:             if (!STORE.hookOnStart(target)) {
481:                 revert Errors.Shared_DisabledHook(target);
482:             }
483: 
484:             
485:             itemIndex = hooks[i].itemIndex;
486: 
487:             
488:             offer = offerItems[itemIndex];
489: 
490:             
491:             if (!offer.isRental()) {
492:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
493:             }
494: 
495:             
496:             try
497:                 IHook(target).onStart(
498:                     rentalWallet,
499:                     offer.token,
500:                     offer.identifier,
501:                     offer.amount,
502:                     hooks[i].extraData
503:                 )
504:             {} catch Error(string memory revertReason) {
505:                 
506:                 revert Errors.Shared_HookFailString(revertReason);
507:             } catch Panic(uint256 errorCode) {
508:                 
509:                 string memory stringErrorCode = LibString.toString(errorCode);
510: 
511:                 
512:                 revert Errors.Shared_HookFailString(
513:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
514:                 );
515:             } catch (bytes memory revertData) {
516:                 
517:                 revert Errors.Shared_HookFailBytes(revertData);
518:             }
519:         }

```


*GitHub* : [475](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L475-L475)

```solidity
695:        for (uint256 i = 0; i < executions.length; ++i) { // <= FOUND
696:             ReceivedItem memory execution = executions[i];
697: 
698:             
699:             if (execution.isERC20()) {
700:                 _checkExpectedRecipient(execution, address(ESCRW));
701:             }
702:             
703:             
704:             else if (execution.isRental()) {
705:                 _checkExpectedRecipient(execution, expectedRentalSafe);
706:             }
707:             
708:             else {
709:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
710:                     execution.itemType
711:                 );
712:             }
713:         }

```


*GitHub* : [695](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L695-L695)

```solidity
205:        for (uint256 i = 0; i < hooks.length; ++i) { // <= FOUND
206:             
207:             target = hooks[i].target;
208: 
209:             
210:             if (!STORE.hookOnStop(target)) {
211:                 revert Errors.Shared_DisabledHook(target);
212:             }
213: 
214:             
215:             itemIndex = hooks[i].itemIndex;
216: 
217:             
218:             item = rentalItems[itemIndex];
219: 
220:             
221:             if (!item.isRental()) {
222:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
223:             }
224: 
225:             
226:             try
227:                 IHook(target).onStop(
228:                     rentalWallet,
229:                     item.token,
230:                     item.identifier,
231:                     item.amount,
232:                     hooks[i].extraData
233:                 )
234:             {} catch Error(string memory revertReason) {
235:                 
236:                 revert Errors.Shared_HookFailString(revertReason);
237:             } catch Panic(uint256 errorCode) {
238:                 
239:                 string memory stringErrorCode = LibString.toString(errorCode);
240: 
241:                 
242:                 revert Errors.Shared_HookFailString(
243:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
244:                 );
245:             } catch (bytes memory revertData) {
246:                 
247:                 revert Errors.Shared_HookFailBytes(revertData);
248:             }
249:         }

```


*GitHub* : [205](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L205-L205)

```solidity
276:        for (uint256 i; i < order.items.length; ++i) { // <= FOUND
277:             if (order.items[i].isRental()) {
278:                 
279:                 _insert(
280:                     rentalAssetUpdates,
281:                     order.items[i].toRentalId(order.rentalWallet),
282:                     order.items[i].amount
283:                 );
284:             }
285:         }

```


*GitHub* : [276](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L276-L276)

```solidity
324:        for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND
325:             
326:             _validateRentalCanBeStoped(
327:                 orders[i].orderType,
328:                 orders[i].endTimestamp,
329:                 orders[i].lender
330:             );
331: 
332:             
333:             for (uint256 j = 0; j < orders[i].items.length; ++j) { // <= FOUND
334:                 
335:                 if (orders[i].items[j].isRental()) {
336:                     _insert(
337:                         rentalAssetUpdates,
338:                         orders[i].items[j].toRentalId(orders[i].rentalWallet),
339:                         orders[i].items[j].amount
340:                     );
341:                 }
342:             }
343: 
344:             
345:             orderHashes[i] = _deriveRentalOrderHash(orders[i]);
346: 
347:             
348:             if (orders[i].hooks.length > 0) {
349:                 _removeHooks(orders[i].hooks, orders[i].items, orders[i].rentalWallet);
350:             }
351: 
352:             
353:             _reclaimRentedItems(orders[i]);
354: 
355:             
356:             _emitRentalOrderStopped(orderHashes[i], msg.sender);
357:         }

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L324-L333)

```solidity
438:        for (uint256 i; i < depLength; ++i) { // <= FOUND
439:             Keycode keycode = dependencies[i];
440: 
441:             
442:             moduleDependents[keycode].push(policy_);
443: 
444:             
445:             getDependentIndex[keycode][policy_] = moduleDependents[keycode].length - 1;
446:         }

```


*GitHub* : [438](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L438-L438)

```solidity
512:        for (uint256 i; i < keycodeLen; ++i) { // <= FOUND
513:             
514:             Module module = Module(getModuleForKeycode[allKeycodes[i]]);
515:             
516:             module.changeKernel(newKernel_);
517:         }

```


*GitHub* : [512](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L512-L512)

```solidity
546:        for (uint256 i; i < depLength; ++i) { // <= FOUND
547:             
548:             dependents[i].configureDependencies();
549:         }

```


*GitHub* : [546](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L546-L546)

```solidity
566:        for (uint256 i = 0; i < reqLength; ++i) { // <= FOUND
567:             
568:             Permissions memory request = requests_[i];
569:             modulePermissions[request.keycode][policy_][request.funcSelector] = grant_;
570: 
571:             emit Events.PermissionsUpdated(
572:                 request.keycode,
573:                 policy_,
574:                 request.funcSelector,
575:                 grant_
576:             );
577:         }

```


*GitHub* : [566](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L566-L566)

```solidity
592:        for (uint256 i; i < depcLength; ++i) { // <= FOUND
593:             
594:             Keycode keycode = dependencies[i];
595:             Policy[] storage dependents = moduleDependents[keycode];
596: 
597:             
598:             uint256 origIndex = getDependentIndex[keycode][policy_];
599: 
600:             
601:             Policy lastPolicy = dependents[dependents.length - 1];
602: 
603:             
604:             dependents[origIndex] = lastPolicy;
605: 
606:             
607:             
608:             dependents.pop();
609: 
610:             
611:             getDependentIndex[keycode][lastPolicy] = origIndex;
612: 
613:             
614:             delete getDependentIndex[keycode][policy_];
615:         }

```


*GitHub* : [592](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L592-L592)
### [G-31]<a name="g-31"></a> Identical Deployments Should be Replaced with Clone
In the context of smart contracts, deploying multiple identical contracts can lead to inefficient use of gas and unnecessarily duplicate code on the blockchain. A more gas-efficient approach is to use a "clone" pattern. By deploying a master contract and then creating clones of it, only the differences between the instances are stored for each clone. This approach leverages the EIP-1167 standard, which defines a minimal proxy contract that points to the implementation contract. Clones can be far cheaper to deploy compared to full instances. So, the resolution is to replace identical deployments with clones, saving on gas and storage space.

*There are 1 instance(s) of this issue:*

```solidity
54:             deploymentAddress := create2( // <= FOUND
55:                 
56:                 callvalue(),
57:                 
58:                 add(initCode, 0x20),
59:                 
60:                 mload(initCode),
61:                 
62:                 salt
63:             )
64:         }

```


*GitHub* : [54](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L54-L54)
### [G-32]<a name="g-32"></a> Redundant Contract Existence Check in Consecutive External Calls
Redundant contract existence checks occur when a smart contract verifies the existence of another contract multiple times consecutively in external calls, leading to unnecessary gas consumption and bloated code. When interacting with another contract, it might be necessary to ensure that the contract is indeed deployed and exists, but performing this check multiple times in consecutive calls is inefficient. Instead of checking the existence of a contract every time before calling its functions, you can check once at the beginning of the sequence and store the result in a local variable. Subsequent interactions can then use this result without additional checks. By removing redundant contract existence checks, developers can save gas and make their code more concise and efficient. Tools like linters or static analyzers can help identify these redundancies during the development phase.

*There are 1 instance(s) of this issue:*

```solidity
294:     function updateHookPath(address to, address hook) external onlyByProxy permissioned {
295:         
296:         if (to.code.length == 0) revert Errors.StorageModule_NotContract(to); // <= FOUND
297: 
298:         
299:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook); // <= FOUND
300: 
301:         
302:         _contractToHook[to] = hook;
303:     }

```


*GitHub* : [294](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L294-L299)
### [G-33]<a name="g-33"></a> Mark Functions That Revert For Normal Users As payable
In Solidity, marking functions as `payable` allows them to accept Ether. If a function is known to revert for regular users (non-admin or specific roles) but needs to be accessible to others, marking it as `payable` can be beneficial. This ensures that even if a regular user accidentally sends Ether to the function, the Ether won't be trapped, as the function reverts, returning the funds. This can save gas by avoiding unnecessary failure handling in the function itself. Resolution: Carefully assess the roles and access patterns, and mark functions that should revert for regular users as `payable` to handle accidental Ether transfers.

*There are 13 instance(s) of this issue:*

```solidity
310:     function grantRole(Role role_, address addr_) public onlyAdmin {
311:         
312:         if (hasRole[addr_][role_])
313:             revert Errors.Kernel_AddressAlreadyHasRole(addr_, role_);
314: 
315:         
316:         ensureValidRole(role_);
317: 
318:         
319:         if (!isRole[role_]) isRole[role_] = true;
320: 
321:         
322:         hasRole[addr_][role_] = true;
323: 
324:         emit Events.RoleGranted(role_, addr_);
325:     }

```


*GitHub* : [310](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L310-L310)

```solidity
333:     function revokeRole(Role role_, address addr_) public onlyAdmin {
334:         
335:         if (!isRole[role_]) revert Errors.Kernel_RoleDoesNotExist(role_);
336: 
337:         
338:         if (!hasRole[addr_][role_])
339:             revert Errors.Kernel_AddressDoesNotHaveRole(addr_, role_);
340: 
341:         
342:         hasRole[addr_][role_] = false;
343: 
344:         emit Events.RoleRevoked(role_, addr_);
345:     }

```


*GitHub* : [333](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L333-L333)

```solidity
99:     function toggleWhitelistDelegate(
100:         address delegate,
101:         bool isEnabled
102:     ) external onlyRole("ADMIN_ADMIN") {
103:         STORE.toggleWhitelistDelegate(delegate, isEnabled);
104:     }

```


*GitHub* : [99](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L99-L99)

```solidity
113:     function toggleWhitelistExtension(
114:         address extension,
115:         bool isEnabled
116:     ) external onlyRole("ADMIN_ADMIN") {
117:         STORE.toggleWhitelistExtension(extension, isEnabled);
118:     }

```


*GitHub* : [113](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L113-L113)

```solidity
126:     function upgradeStorage(address newImplementation) external onlyRole("ADMIN_ADMIN") {
127:         STORE.upgrade(newImplementation);
128:     }

```


*GitHub* : [126](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L126-L126)

```solidity
134:     function freezeStorage() external onlyRole("ADMIN_ADMIN") {
135:         STORE.freeze();
136:     }

```


*GitHub* : [134](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L134-L134)

```solidity
144:     function upgradePaymentEscrow(
145:         address newImplementation
146:     ) external onlyRole("ADMIN_ADMIN") {
147:         ESCRW.upgrade(newImplementation);
148:     }

```


*GitHub* : [144](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L144-L144)

```solidity
154:     function freezePaymentEscrow() external onlyRole("ADMIN_ADMIN") {
155:         ESCRW.freeze();
156:     }

```


*GitHub* : [154](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L154-L154)

```solidity
164:     function skim(address token, address to) external onlyRole("ADMIN_ADMIN") {
165:         ESCRW.skim(token, to);
166:     }

```


*GitHub* : [164](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L164-L164)

```solidity
173:     function setFee(uint256 feeNumerator) external onlyRole("ADMIN_ADMIN") {
174:         ESCRW.setFee(feeNumerator);
175:     }

```


*GitHub* : [173](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L173-L173)

```solidity
733:     function validateOrder(
734:         ZoneParameters calldata zoneParams
735:     ) external override onlyRole("SEAPORT") returns (bytes4 validOrderMagicValue) {
736:         
737:         (RentPayload memory payload, bytes memory signature) = abi.decode(
738:             zoneParams.extraData,
739:             (RentPayload, bytes)
740:         );
741: 
742:         
743:         SeaportPayload memory seaportPayload = SeaportPayload({
744:             orderHash: zoneParams.orderHash,
745:             zoneHash: zoneParams.zoneHash,
746:             offer: zoneParams.offer,
747:             consideration: zoneParams.consideration,
748:             totalExecutions: zoneParams.totalExecutions,
749:             fulfiller: zoneParams.fulfiller,
750:             offerer: zoneParams.offerer
751:         });
752: 
753:         
754:         _validateProtocolSignatureExpiration(payload.expiration);
755: 
756:         
757:         _validateFulfiller(payload.intendedFulfiller, seaportPayload.fulfiller);
758: 
759:         
760:         address signer = _recoverSignerFromPayload(
761:             _deriveRentPayloadHash(payload),
762:             signature
763:         );
764: 
765:         
766:         if (!kernel.hasRole(signer, toRole("CREATE_SIGNER"))) {
767:             revert Errors.CreatePolicy_UnauthorizedCreatePolicySigner();
768:         }
769: 
770:         
771:         _rentFromZone(payload, seaportPayload);
772: 
773:         
774:         validOrderMagicValue = ZoneInterface.validateOrder.selector;
775:     }

```


*GitHub* : [733](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L733-L733)

```solidity
362:     function updateHookPath(address to, address hook) external onlyRole("GUARD_ADMIN") {
363:         STORE.updateHookPath(to, hook);
364:     }

```


*GitHub* : [362](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L362-L362)

```solidity
373:     function updateHookStatus(
374:         address hook,
375:         uint8 bitmap
376:     ) external onlyRole("GUARD_ADMIN") {
377:         STORE.updateHookStatus(hook, bitmap);
378:     }

```


*GitHub* : [373](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L373-L373)
### [G-34]<a name="g-34"></a> State variable read in a loop
Reading a state variable inside a loop in Solidity can be gas-inefficient, particularly in older versions of the language. Each read from a state variable in a loop incurs a gas cost, and these costs can accumulate quickly if the loop iterates many times. As a resolution, developers often manually cache the state variable outside the loop, reducing the number of state reads. By reading the variable only once and using the cached value within the loop, the gas costs can be significantly reduced. This approach requires careful consideration of the code's logic but can lead to more efficient contract execution.

*There are 1 instance(s) of this issue:*

```solidity
566:        for (uint256 i = 0; i < reqLength; ++i) {
567:             
568:             Permissions memory request = requests_[i];
569:             modulePermissions[request.keycode][policy_][request.funcSelector] = grant_; // <= FOUND
570: 
571:             emit Events.PermissionsUpdated(
572:                 request.keycode,
573:                 policy_,
574:                 request.funcSelector,
575:                 grant_
576:             );
577:         }

```


*GitHub* : [569](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L569-L569)
### [G-35]<a name="g-35"></a> Function names can be optimized
Function names in Solidity contracts can be optimized to save gas during both deployment and execution. Method IDs are the first four bytes of the keccak256 hash of the function signature, and having two leading zero bytes can save 128 gas each during deployment. Additionally, renaming functions to have lower method IDs can save 22 gas per call, per sorted position shifted. This optimization leverages the way EVM handles data storage, making the execution more efficient. While these savings might seem minor, they can add up in contracts with numerous calls, contributing to more economical and efficient code.

*There are 11 instance(s) of this issue:*

```solidity
23: contract PaymentEscrowBase  // <= FOUND

```


*GitHub* : [23](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L23-L23)

```solidity
37: contract PaymentEscrow is Proxiable, Module, PaymentEscrowBase  // <= FOUND

```


*GitHub* : [37](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L37-L37)

```solidity
14: contract StorageBase  // <= FOUND

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L14-L14)

```solidity
66: contract Storage is Proxiable, Module, StorageBase  // <= FOUND

```


*GitHub* : [66](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L66-L66)

```solidity
15: contract Admin is Policy  // <= FOUND

```


*GitHub* : [15](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L15-L15)

```solidity
41: contract Create is Policy, Signer, Zone, Accumulator  // <= FOUND

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L41-L41)

```solidity
22: contract Factory is Policy  // <= FOUND

```


*GitHub* : [22](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L22-L22)

```solidity
39: contract Guard is Policy, BaseGuard  // <= FOUND

```


*GitHub* : [39](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L39-L39)

```solidity
34: contract Stop is Policy, Signer, Reclaimer, Accumulator  // <= FOUND

```


*GitHub* : [34](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L34-L34)

```solidity
14: contract Create2Deployer  // <= FOUND

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L14-L14)

```solidity
206: contract Kernel  // <= FOUND

```


*GitHub* : [206](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L206-L206)
### [G-36]<a name="g-36"></a> Assembly let var only used on once
If a variable is only once, it makes more sense to use the value the variable holds directly

*There are 1 instance(s) of this issue:*

```solidity
40:         assembly {
41:             
42:             if eq(mload(rentalAssets), 0) {
43:                 
44:                 mstore(rentalAssets, 0x20)
45: 
46:                 
47:                 mstore(add(0x20, rentalAssets), 0x00)
48:             }
49: 
50:             
51:             
52:             let newByteDataSize := add(mload(rentalAssets), 0x40) // <= FOUND
53: 
54:             
55:             let rentalAssetElementPtr := add(rentalAssets, 0x20)
56: 
57:             
58:             let elements := add(mload(rentalAssetElementPtr), 1)
59: 
60:             
61:             
62:             
63:             
64:             let newItemPosition := add(
65:                 rentalAssetElementPtr,
66:                 sub(mul(elements, 0x40), 0x20)
67:             )
68: 
69:             
70:             mstore(rentalAssets, newByteDataSize) // <= FOUND
71: 
72:             
73:             mstore(rentalAssetElementPtr, elements)
74: 
75:             
76:             mstore(newItemPosition, _rentalId)
77: 
78:             
79:             mstore(add(newItemPosition, 0x20), rentalAssetAmount)
80: 
81:             
82:             
83:             mstore(0x40, add(newItemPosition, 0x40))
84:         }

```


*GitHub* : [40](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L40-L70)
### [G-37]<a name="g-37"></a> Use assembly to validate msg.sender
Utilizing assembly for validating `msg.sender` can potentially save gas as it allows for more direct and efficient access to Ethereum’s EVM opcodes, bypassing some of the overhead introduced by Solidity’s higher-level abstractions. However, this practice requires deep expertise in EVM, as incorrect implementation can introduce critical vulnerabilities. It is a trade-off between gas efficiency and code safety.

*There are 6 instance(s) of this issue:*

```solidity
141:                 revert Errors.StopPolicy_CannotStopOrder(block.timestamp, msg.sender); // <= FOUND

```


*GitHub* : [141](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L141-L141)

```solidity
38:             revert Errors.Create2Deployer_UnauthorizedSender(msg.sender, salt); // <= FOUND

```


*GitHub* : [38](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L38-L38)

```solidity
41:         if (msg.sender != address(kernel)) // <= FOUND
42:             revert Errors.KernelAdapter_OnlyKernel(msg.sender); // <= FOUND

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L41-L42)

```solidity
79:             revert Errors.Module_PolicyNotAuthorized(msg.sender); // <= FOUND

```


*GitHub* : [79](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L79-L79)

```solidity
255:         if (msg.sender != executor) revert Errors.Kernel_OnlyExecutor(msg.sender); // <= FOUND

```


*GitHub* : [255](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L255-L255)

```solidity
263:         if (msg.sender != admin) revert Errors.Kernel_OnlyAdmin(msg.sender); // <= FOUND

```


*GitHub* : [263](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L263-L263)
### [G-38]<a name="g-38"></a> Simple checks for zero uint can be done using assembly to save gas
Using assembly for simple zero checks on unsigned integers can save gas due to lower-level, optimized operations. 

**Resolution**: Implement inline assembly with Solidity's `assembly` block to perform zero checks. Ensure thorough testing and verification, as assembly lacks the safety checks of high-level Solidity, potentially introducing vulnerabilities if not used carefully.

*There are 8 instance(s) of this issue:*

```solidity
296:         
297:         if (to.code.length == 0) revert Errors.StorageModule_NotContract(to); // <= FOUND

```


*GitHub* : [296](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L296-L297)

```solidity
299: 
300:         
301:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook); // <= FOUND

```


*GitHub* : [299](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L299-L301)

```solidity
299:         
300:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook); // <= FOUND

```


*GitHub* : [299](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L299-L300)

```solidity
127: 
128:         
129:         return rentedAssets[rentalId] != 0; // <= FOUND

```


*GitHub* : [127](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L127-L129)

```solidity
141: 
142:         
143:         
144:         return hookStatus[hook] != 0 ? hook : address(0); // <= FOUND

```


*GitHub* : [141](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L141-L144)

```solidity
151:         
152:         return (uint8(1) & hookStatus[hook]) != 0; // <= FOUND

```


*GitHub* : [151](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L151-L152)

```solidity
161:         
162:         return uint8(2) & hookStatus[hook] != 0; // <= FOUND

```


*GitHub* : [161](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L161-L162)

```solidity
171:         
172:         return uint8(4) & hookStatus[hook] != 0; // <= FOUND

```


*GitHub* : [171](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L171-L172)
### [G-39]<a name="g-39"></a> Trade-offs Between Modifiers and Internal Functions
In Solidity, both modifiers and internal functions can be used to modularize and reuse code, but they have different trade-offs.

Modifiers are primarily used to augment the behavior of functions, often for checks or validations. They can access parameters of the function they modify and are integrated into the function’s code at compile time. This makes them syntactically cleaner for repetitive precondition checks. However, modifiers can sometimes lead to less readable code, especially when the logic is complex or when multiple modifiers are used on a single function.

Internal functions, on the other hand, offer more flexibility. They can contain complex logic, return values, and be called from other functions. This makes them more suitable for reusable chunks of business logic. Since internal functions are separate entities, they can be more readable and easier to test in isolation compared to modifiers.

Using internal functions can result in slightly more gas consumption, as it involves an internal function call. However, this cost is usually minimal and can be a worthwhile trade-off for increased code clarity and maintainability.

In summary, while modifiers offer a concise way to include checks and simple logic across multiple functions, internal functions provide more flexibility and are better suited for complex and reusable code. The choice between the two should be based on the specific use case, considering factors like code complexity, readability, and gas efficiency.

*There are 52 instance(s) of this issue:*

```solidity
88:     function _calculateFee(uint256 amount) internal view returns (uint256)  // <= FOUND

```


*GitHub* : [88](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L88-L88)

```solidity
100:     function _safeTransfer(address token, address to, uint256 value) internal  // <= FOUND

```


*GitHub* : [100](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L100-L100)

```solidity
132:     function _calculatePaymentProRata( // <= FOUND
133:         uint256 amount, // <= FOUND
134:         uint256 elapsedTime, // <= FOUND
135:         uint256 totalTime // <= FOUND
136:     ) internal pure returns (uint256 renterAmount, uint256 lenderAmount)  // <= FOUND

```


*GitHub* : [132](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L132-L136)

```solidity
159:     function _settlePaymentProRata( // <= FOUND
160:         address token, // <= FOUND
161:         uint256 amount, // <= FOUND
162:         address lender, // <= FOUND
163:         address renter, // <= FOUND
164:         uint256 elapsedTime, // <= FOUND
165:         uint256 totalTime // <= FOUND
166:     ) internal  // <= FOUND

```


*GitHub* : [159](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L159-L166)

```solidity
190:     function _settlePaymentInFull( // <= FOUND
191:         address token, // <= FOUND
192:         uint256 amount, // <= FOUND
193:         SettleTo settleTo, // <= FOUND
194:         address lender, // <= FOUND
195:         address renter // <= FOUND
196:     ) internal  // <= FOUND

```


*GitHub* : [190](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L190-L196)

```solidity
215:     function _settlePayment( // <= FOUND
216:         Item[] calldata items, // <= FOUND
217:         OrderType orderType, // <= FOUND
218:         address lender, // <= FOUND
219:         address renter, // <= FOUND
220:         uint256 start, // <= FOUND
221:         uint256 end // <= FOUND
222:     ) internal  // <= FOUND

```


*GitHub* : [215](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L215-L222)

```solidity
292:     function _decreaseDeposit(address token, uint256 amount) internal  // <= FOUND

```


*GitHub* : [292](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L292-L292)

```solidity
304:     function _increaseDeposit(address token, uint256 amount) internal  // <= FOUND

```


*GitHub* : [304](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L304-L304)

```solidity
32:     function _insert( // <= FOUND
33:         bytes memory rentalAssets, // <= FOUND
34:         RentalId rentalId, // <= FOUND
35:         uint256 rentalAssetAmount // <= FOUND
36:     ) internal pure  // <= FOUND

```


*GitHub* : [32](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L32-L36)

```solidity
96:     function _convertToStatic( // <= FOUND
97:         bytes memory rentalAssetUpdates // <= FOUND
98:     ) internal pure returns (RentalAssetUpdate[] memory updates)  // <= FOUND

```


*GitHub* : [96](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L96-L98)

```solidity
76:     function _validateFulfiller( // <= FOUND
77:         address intendedFulfiller, // <= FOUND
78:         address actualFulfiller // <= FOUND
79:     ) internal pure  // <= FOUND

```


*GitHub* : [76](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L76-L79)

```solidity
94:     function _validateProtocolSignatureExpiration(uint256 expiration) internal view  // <= FOUND

```


*GitHub* : [94](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L94-L94)

```solidity
107:     function _recoverSignerFromPayload( // <= FOUND
108:         bytes32 payloadHash, // <= FOUND
109:         bytes memory signature // <= FOUND
110:     ) internal view returns (address)  // <= FOUND

```


*GitHub* : [107](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L107-L110)

```solidity
125:     function _deriveItemHash(Item memory item) internal view returns (bytes32)  // <= FOUND

```


*GitHub* : [125](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L125-L125)

```solidity
147:     function _deriveHookHash(Hook memory hook) internal view returns (bytes32)  // <= FOUND

```


*GitHub* : [147](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L147-L147)

```solidity
162:     function _deriveRentalOrderHash( // <= FOUND
163:         RentalOrder memory order // <= FOUND
164:     ) internal view returns (bytes32)  // <= FOUND

```


*GitHub* : [162](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L162-L164)

```solidity
204:     function _deriveOrderFulfillmentHash( // <= FOUND
205:         OrderFulfillment memory fulfillment // <= FOUND
206:     ) internal view returns (bytes32)  // <= FOUND

```


*GitHub* : [204](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L204-L206)

```solidity
218:     function _deriveOrderMetadataHash( // <= FOUND
219:         OrderMetadata memory metadata // <= FOUND
220:     ) internal view returns (bytes32)  // <= FOUND

```


*GitHub* : [218](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L218-L220)

```solidity
248:     function _deriveRentPayloadHash( // <= FOUND
249:         RentPayload memory payload // <= FOUND
250:     ) internal view returns (bytes32)  // <= FOUND

```


*GitHub* : [248](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L248-L250)

```solidity
273:     function _deriveDomainSeparator( // <= FOUND
274:         bytes32 _eip712DomainTypeHash, // <= FOUND
275:         bytes32 _nameHash, // <= FOUND
276:         bytes32 _versionHash // <= FOUND
277:     ) internal view virtual returns (bytes32)  // <= FOUND

```


*GitHub* : [273](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L273-L277)

```solidity
298:     function _deriveTypehashes() // <= FOUND
299:         internal // <= FOUND
300:         view // <= FOUND
301:         returns ( // <= FOUND
302:             bytes32 nameHash, // <= FOUND
303:             bytes32 versionHash, // <= FOUND
304:             bytes32 eip712DomainTypehash, // <= FOUND
305:             bytes32 domainSeparator // <= FOUND
306:         ) // <= FOUND
307:      // <= FOUND

```


*GitHub* : [298](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L298-L307)

```solidity
339:     function _deriveRentalTypehashes() // <= FOUND
340:         internal // <= FOUND
341:         pure // <= FOUND
342:         returns ( // <= FOUND
343:             bytes32 itemTypeHash, // <= FOUND
344:             bytes32 hookTypeHash, // <= FOUND
345:             bytes32 rentalOrderTypeHash, // <= FOUND
346:             bytes32 orderFulfillmentTypeHash, // <= FOUND
347:             bytes32 orderMetadataTypeHash, // <= FOUND
348:             bytes32 rentPayloadTypeHash // <= FOUND
349:         ) // <= FOUND
350:      // <= FOUND

```


*GitHub* : [339](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L339-L350)

```solidity
165:     function _emitRentalOrderStarted( // <= FOUND
166:         RentalOrder memory order, // <= FOUND
167:         bytes32 orderHash, // <= FOUND
168:         bytes memory extraData // <= FOUND
169:     ) internal  // <= FOUND

```


*GitHub* : [165](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L165-L169)

```solidity
195:     function _processBaseOrderOffer( // <= FOUND
196:         Item[] memory rentalItems, // <= FOUND
197:         SpentItem[] memory offers, // <= FOUND
198:         uint256 startIndex // <= FOUND
199:     ) internal pure  // <= FOUND

```


*GitHub* : [195](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L195-L199)

```solidity
247:     function _processPayOrderOffer( // <= FOUND
248:         Item[] memory rentalItems, // <= FOUND
249:         SpentItem[] memory offers, // <= FOUND
250:         uint256 startIndex // <= FOUND
251:     ) internal pure  // <= FOUND

```


*GitHub* : [247](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L247-L251)

```solidity
326:     function _processBaseOrderConsideration( // <= FOUND
327:         Item[] memory rentalItems, // <= FOUND
328:         ReceivedItem[] memory considerations, // <= FOUND
329:         uint256 startIndex // <= FOUND
330:     ) internal pure  // <= FOUND

```


*GitHub* : [326](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L326-L330)

```solidity
367:     function _processPayeeOrderConsideration( // <= FOUND
368:         ReceivedItem[] memory considerations // <= FOUND
369:     ) internal pure  // <= FOUND

```


*GitHub* : [367](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L367-L369)

```solidity
411:     function _convertToItems( // <= FOUND
412:         SpentItem[] memory offers, // <= FOUND
413:         ReceivedItem[] memory considerations, // <= FOUND
414:         OrderType orderType // <= FOUND
415:     ) internal pure returns (Item[] memory items)  // <= FOUND

```


*GitHub* : [411](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L411-L415)

```solidity
464:     function _addHooks( // <= FOUND
465:         Hook[] memory hooks, // <= FOUND
466:         SpentItem[] memory offerItems, // <= FOUND
467:         address rentalWallet // <= FOUND
468:     ) internal  // <= FOUND

```


*GitHub* : [464](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L464-L468)

```solidity
530:     function _rentFromZone( // <= FOUND
531:         RentPayload memory payload, // <= FOUND
532:         SeaportPayload memory seaportPayload // <= FOUND
533:     ) internal  // <= FOUND

```


*GitHub* : [530](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L530-L533)

```solidity
626:     function _isValidOrderMetadata( // <= FOUND
627:         OrderMetadata memory metadata, // <= FOUND
628:         bytes32 zoneHash // <= FOUND
629:     ) internal view  // <= FOUND

```


*GitHub* : [626](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L626-L629)

```solidity
647:     function _isValidSafeOwner(address owner, address safe) internal view  // <= FOUND

```


*GitHub* : [647](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L647-L647)

```solidity
666:     function _checkExpectedRecipient( // <= FOUND
667:         ReceivedItem memory execution, // <= FOUND
668:         address expectedRecipient // <= FOUND
669:     ) internal pure  // <= FOUND

```


*GitHub* : [666](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L666-L669)

```solidity
691:     function _executionInvariantChecks( // <= FOUND
692:         ReceivedItem[] memory executions, // <= FOUND
693:         address expectedRentalSafe // <= FOUND
694:     ) internal view  // <= FOUND

```


*GitHub* : [691](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L691-L694)

```solidity
111:     function _emitRentalOrderStopped(bytes32 seaportOrderHash, address stopper) internal  // <= FOUND

```


*GitHub* : [111](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L111-L111)

```solidity
126:     function _validateRentalCanBeStoped( // <= FOUND
127:         OrderType orderType, // <= FOUND
128:         uint256 endTimestamp, // <= FOUND
129:         address expectedLender // <= FOUND
130:     ) internal view  // <= FOUND

```


*GitHub* : [126](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L126-L130)

```solidity
166:     function _reclaimRentedItems(RentalOrder memory order) internal  // <= FOUND

```


*GitHub* : [166](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L166-L166)

```solidity
194:     function _removeHooks( // <= FOUND
195:         Hook[] calldata hooks, // <= FOUND
196:         Item[] calldata rentalItems, // <= FOUND
197:         address rentalWallet // <= FOUND
198:     ) internal  // <= FOUND

```


*GitHub* : [194](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L194-L198)

```solidity
180:     function getModuleAddress(Keycode keycode_) internal view returns (address)  // <= FOUND

```


*GitHub* : [180](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L180-L180)

```solidity
356:     function _installModule(Module newModule_) internal  // <= FOUND

```


*GitHub* : [356](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L356-L356)

```solidity
383:     function _upgradeModule(Module newModule_) internal  // <= FOUND

```


*GitHub* : [383](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L383-L383)

```solidity
418:     function _activatePolicy(Policy policy_) internal  // <= FOUND

```


*GitHub* : [418](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L418-L418)

```solidity
457:     function _deactivatePolicy(Policy policy_) internal  // <= FOUND

```


*GitHub* : [457](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L457-L457)

```solidity
508:     function _migrateKernel(Kernel newKernel_) internal  // <= FOUND

```


*GitHub* : [508](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L508-L508)

```solidity
540:     function _reconfigurePolicies(Keycode keycode_) internal  // <= FOUND

```


*GitHub* : [540](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L540-L540)

```solidity
560:     function _setPolicyPermissions( // <= FOUND
561:         Policy policy_, // <= FOUND
562:         Permissions[] memory requests_, // <= FOUND
563:         bool grant_ // <= FOUND
564:     ) internal  // <= FOUND

```


*GitHub* : [560](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L560-L564)

```solidity
586:     function _pruneFromDependents(Policy policy_) internal  // <= FOUND

```


*GitHub* : [586](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L586-L586)

```solidity
40:     modifier onlyKernel()  // <= FOUND

```


*GitHub* : [40](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L40-L40)

```solidity
77:     modifier permissioned()  // <= FOUND

```


*GitHub* : [77](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L77-L77)

```solidity
130:     modifier onlyRole(bytes32 role_)  // <= FOUND

```


*GitHub* : [130](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L130-L130)

```solidity
254:     modifier onlyExecutor()  // <= FOUND

```


*GitHub* : [254](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L254-L254)

```solidity
262:     modifier onlyAdmin()  // <= FOUND

```


*GitHub* : [262](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L262-L262)
### [G-40]<a name="g-40"></a> Using nested if to save gas
Using nested `if` statements instead of logical AND (`&&`) operators can potentially save gas in Solidity contracts. When a series of conditions are connected with `&&`, all conditions must be evaluated even if the first one fails. In contrast, nested `if` statements allow for short-circuiting; if the first condition fails, the rest are skipped, saving gas. This approach is more gas-efficient, especially when dealing with complex or gas-intensive conditions. However, it's crucial to balance gas savings with code readability and maintainability, ensuring that the code remains clear and easy to understand.

*There are 5 instance(s) of this issue:*

```solidity
115:         if (!success || (data.length != 0 && !abi.decode(data, (bool)))) { // <= FOUND
116:             revert Errors.PaymentEscrowModule_PaymentTransferFailed(token, to, value);
117:         }

```


*GitHub* : [115](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L115-L115)

```solidity
324:         if (operation == Enum.Operation.DelegateCall && !STORE.whitelistedDelegates(to)) { // <= FOUND
325:             revert Errors.GuardPolicy_UnauthorizedDelegateCall(to);
326:         }

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L324-L324)

```solidity
338:         if (hook != address(0) && isActive) { // <= FOUND
339:             _forwardToHook(hook, msg.sender, to, value, data);
340:         }

```


*GitHub* : [338](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L338-L338)

```solidity
148:             if (!isLender && (!hasExpired)) { // <= FOUND
149:                 revert Errors.StopPolicy_CannotStopOrder(block.timestamp, msg.sender);
150:             }

```


*GitHub* : [148](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L148-L148)

```solidity
255:                 if (orderType.isPayOrder() && !isRentalOver) { // <= FOUND
256:                     
257:                     _settlePaymentProRata(
258:                         item.token,
259:                         paymentAmount,
260:                         lender,
261:                         renter,
262:                         elapsedTime,
263:                         totalTime
264:                     );
265:                 }

```


*GitHub* : [255](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L255-L255)
### [G-41]<a name="g-41"></a> Optimize Deployment Size by Fine-tuning IPFS Hash
Optimizing the deployment size of a smart contract is vital to minimize gas costs, and one way to achieve this is by fine-tuning the IPFS hash appended by the Solidity compiler as metadata. This metadata, consisting of 53 bytes, increases the gas required for contract deployment by approximately 10,600 gas due to bytecode costs, and additionally, up to 848 gas due to calldata costs, depending on the proportion of zero and non-zero bytes. Utilize the --no-cbor-metadata compiler flag to prevent the compiler from appending metadata. However, this approach has a drawback as it can complicate the contract verification process on block explorers like Etherscan, potentially reducing transparency.

*There are 11 instance(s) of this issue:*

```solidity
23: contract PaymentEscrowBase  // <= FOUND

```


*GitHub* : [23](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L23-L23)

```solidity
37: contract PaymentEscrow is Proxiable, Module, PaymentEscrowBase  // <= FOUND

```


*GitHub* : [37](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L37-L37)

```solidity
14: contract StorageBase  // <= FOUND

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L14-L14)

```solidity
66: contract Storage is Proxiable, Module, StorageBase  // <= FOUND

```


*GitHub* : [66](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L66-L66)

```solidity
15: contract Admin is Policy  // <= FOUND

```


*GitHub* : [15](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L15-L15)

```solidity
41: contract Create is Policy, Signer, Zone, Accumulator  // <= FOUND

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L41-L41)

```solidity
22: contract Factory is Policy  // <= FOUND

```


*GitHub* : [22](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L22-L22)

```solidity
39: contract Guard is Policy, BaseGuard  // <= FOUND

```


*GitHub* : [39](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L39-L39)

```solidity
34: contract Stop is Policy, Signer, Reclaimer, Accumulator  // <= FOUND

```


*GitHub* : [34](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L34-L34)

```solidity
14: contract Create2Deployer  // <= FOUND

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L14-L14)

```solidity
206: contract Kernel  // <= FOUND

```


*GitHub* : [206](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L206-L206)
### [G-42]<a name="g-42"></a> Avoid Unnecessary Public Variables
Public state variables in Solidity automatically generate getter functions, increasing contract size and potentially leading to higher deployment and interaction costs. To optimize gas usage and contract efficiency, minimize the use of public variables unless external access is necessary. Instead, use internal or private visibility combined with explicit getter functions when required. This practice not only reduces contract size but also provides better control over data access and manipulation, enhancing security and readability. Prioritize lean, efficient contracts to ensure cost-effectiveness and better performance on the blockchain.

*There are 16 instance(s) of this issue:*

```solidity
28: uint256 public fee; // <= FOUND

```


*GitHub* : [28](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L28-L28)

```solidity
36: uint256 public totalSafes; // <= FOUND

```


*GitHub* : [36](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L36-L36)

```solidity
28: Storage public STORE; // <= FOUND

```


*GitHub* : [28](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L28-L28)

```solidity
54: PaymentEscrow public ESCRW; // <= FOUND

```


*GitHub* : [54](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L54-L54)

```solidity
31: Stop public immutable stopPolicy; // <= FOUND

```


*GitHub* : [31](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L31-L31)

```solidity
32: Guard public immutable guardPolicy; // <= FOUND

```


*GitHub* : [32](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L32-L32)

```solidity
35: TokenCallbackHandler public immutable fallbackHandler; // <= FOUND

```


*GitHub* : [35](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L35-L35)

```solidity
36: SafeProxyFactory public immutable safeProxyFactory; // <= FOUND

```


*GitHub* : [36](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L36-L36)

```solidity
37: SafeL2 public immutable safeSingleton; // <= FOUND

```


*GitHub* : [37](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L37-L37)

```solidity
208: address public executor; // <= FOUND

```


*GitHub* : [208](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L208-L208)

```solidity
209: address public admin; // <= FOUND

```


*GitHub* : [209](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L209-L209)

```solidity
212: Keycode[] public allKeycodes; // <= FOUND

```


*GitHub* : [212](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L212-L212)

```solidity
225: Policy[] public activePolicies; // <= FOUND

```


*GitHub* : [225](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L225-L225)

```solidity
25: Kernel public kernel; // <= FOUND

```


*GitHub* : [25](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L25-L25)

```solidity
90: function KEYCODE() public pure virtual returns (Keycode); // <= FOUND

```


*GitHub* : [90](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L90-L90)

```solidity
116: bool public isActive; // <= FOUND

```


*GitHub* : [116](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L116-L116)
### [G-43]<a name="g-43"></a> Avoid emitting event on every iteration
Emitting events within a loop can cause significant gas consumption due to repeated I/O operations. Instead, accumulate changes in memory and emit a single event post-loop with aggregated data. This approach improves contract efficiency, reduces gas costs, and simplifies event tracking for event listeners.

*There are 1 instance(s) of this issue:*

```solidity
566:        for (uint256 i = 0; i < reqLength; ++i) {
567:             
568:             Permissions memory request = requests_[i];
569:             modulePermissions[request.keycode][policy_][request.funcSelector] = grant_;
570: 
571:             emit Events.PermissionsUpdated( // <= FOUND
572:                 request.keycode,
573:                 policy_,
574:                 request.funcSelector,
575:                 grant_
576:             );
577:         }

```


*GitHub* : [571](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L571-L571)
### [G-44]<a name="g-44"></a> Inline modifiers used only once

*There are 1 instance(s) of this issue:*

```solidity
254:     modifier onlyExecutor() { // <= FOUND
255:         if (msg.sender != executor) revert Errors.Kernel_OnlyExecutor(msg.sender);
256:         _;
257:     }

```


*GitHub* : [254](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L254-L254)
### [G-45]<a name="g-45"></a> Use s.x = s.x + y instead of s.x += y for memory structs (same for -= etc)
In Solidity, optimizing gas usage is crucial, particularly for frequently executed operations. For memory structs, using explicit assignment (e.g., `s.x = s.x + y`) instead of shorthand operations (e.g., `s.x += y`) can result in a minor gas saving, around 100 gas. This difference arises from the way the Solidity compiler optimizes bytecode. While such savings might seem small, they can add up in contracts with high transaction volume. This optimization applies to other compound assignment operators like `-=` and `*=` as well. It's a subtle efficiency gain that developers can leverage, especially in complex contracts where every gas unit counts.

*There are 4 instance(s) of this issue:*

```solidity
189:     function addRentals(
190:         bytes32 orderHash,
191:         RentalAssetUpdate[] memory rentalAssetUpdates
192:     ) external onlyByProxy permissioned {
193:         
194:         orders[orderHash] = true;
195: 
196:         
197:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {
198:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
199: 
200:             
201:             rentedAssets[asset.rentalId] += asset.amount; // <= FOUND
202:         }
203:     }

```


*GitHub* : [189](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L189-L201)

```solidity
215:     function _settlePayment(
216:         Item[] calldata items,
217:         OrderType orderType,
218:         address lender,
219:         address renter,
220:         uint256 start,
221:         uint256 end
222:     ) internal {
223:         
224:         uint256 elapsedTime = block.timestamp - start;
225:         uint256 totalTime = end - start;
226: 
227:         
228:         bool isRentalOver = elapsedTime >= totalTime;
229: 
230:         
231:         for (uint256 i = 0; i < items.length; ++i) {
232:             
233:             Item memory item = items[i];
234: 
235:             
236:             if (item.isERC20()) { // <= FOUND
237:                 
238:                 
239:                 uint256 paymentAmount = item.amount; // <= FOUND
240: 
241:                 
242:                 if (fee != 0) {
243:                     
244:                     uint256 paymentFee = _calculateFee(paymentAmount);
245: 
246:                     
247:                     paymentAmount -= paymentFee; // <= FOUND
248:                 }
249: 
250:                 
251:                 
252:                 _decreaseDeposit(item.token, item.amount); // <= FOUND
253: 
254:                 
255:                 if (orderType.isPayOrder() && !isRentalOver) {
256:                     
257:                     _settlePaymentProRata(
258:                         item.token, // <= FOUND
259:                         paymentAmount,
260:                         lender,
261:                         renter,
262:                         elapsedTime,
263:                         totalTime
264:                     );
265:                 }
266:                 
267:                 else if (
268:                     (orderType.isPayOrder() && isRentalOver) || orderType.isBaseOrder()
269:                 ) {
270:                     
271:                     _settlePaymentInFull(
272:                         item.token, // <= FOUND
273:                         paymentAmount,
274:                         item.settleTo, // <= FOUND
275:                         lender,
276:                         renter
277:                     );
278:                 } else {
279:                     revert Errors.Shared_OrderTypeNotSupported(uint8(orderType));
280:                 }
281:             }
282:         }
283:     }

```


*GitHub* : [215](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L215-L274)

```solidity
216:     function removeRentals(
217:         bytes32 orderHash,
218:         RentalAssetUpdate[] calldata rentalAssetUpdates
219:     ) external onlyByProxy permissioned {
220:         
221:         if (!orders[orderHash]) {
222:             revert Errors.StorageModule_OrderDoesNotExist(orderHash);
223:         } else {
224:             
225:             delete orders[orderHash];
226:         }
227: 
228:         
229:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {
230:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
231: 
232:             
233:             rentedAssets[asset.rentalId] -= asset.amount; // <= FOUND
234:         }
235:     }

```


*GitHub* : [216](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L216-L233)

```solidity
244:     function removeRentalsBatch(
245:         bytes32[] calldata orderHashes,
246:         RentalAssetUpdate[] calldata rentalAssetUpdates
247:     ) external onlyByProxy permissioned {
248:         
249:         for (uint256 i = 0; i < orderHashes.length; ++i) {
250:             
251:             if (!orders[orderHashes[i]]) {
252:                 revert Errors.StorageModule_OrderDoesNotExist(orderHashes[i]);
253:             } else {
254:                 
255:                 delete orders[orderHashes[i]];
256:             }
257:         }
258: 
259:         
260:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {
261:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
262: 
263:             
264:             rentedAssets[asset.rentalId] -= asset.amount; // <= FOUND
265:         }
266:     }

```


*GitHub* : [244](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L244-L264)
### [G-46]<a name="g-46"></a> ++X costs slightly less gas than X++ (same with --)
Move the ++/-- action to the left of the variable

*There are 4 instance(s) of this issue:*

```solidity
273: 
274:                 
275:                 totalRentals++; // <= FOUND

```


*GitHub* : [275](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L275-L275)

```solidity
293: 
294:                 
295:                 totalPayments++; // <= FOUND

```


*GitHub* : [295](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L295-L295)

```solidity
293:                 totalPayments++; // <= FOUND

```


*GitHub* : [293](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L293-L293)

```solidity
273:                 totalRentals++; // <= FOUND

```


*GitHub* : [273](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L273-L273)
### [G-47]<a name="g-47"></a> Variable declared within iteration
Please elaborate and generalise the following with detail and  feel free to use your own knowledge and lmit ur words to 100 words please:

*There are 5 instance(s) of this issue:*

```solidity
231:        for (uint256 i = 0; i < items.length; ++i) { // <= FOUND
232:             
233:             Item memory item = items[i];
234: 
235:             
236:             if (item.isERC20()) {
237:                 
238:                 
239:                 uint256 paymentAmount = item.amount;
240: 
241:                 
242:                 if (fee != 0) {
243:                     
244:                     uint256 paymentFee = _calculateFee(paymentAmount);
245: 
246:                     
247:                     paymentAmount -= paymentFee;
248:                 }
249: 
250:                 
251:                 
252:                 _decreaseDeposit(item.token, item.amount);
253: 
254:                 
255:                 if (orderType.isPayOrder() && !isRentalOver) {
256:                     
257:                     _settlePaymentProRata(
258:                         item.token,
259:                         paymentAmount,
260:                         lender,
261:                         renter,
262:                         elapsedTime,
263:                         totalTime
264:                     );
265:                 }
266:                 
267:                 else if (
268:                     (orderType.isPayOrder() && isRentalOver) || orderType.isBaseOrder()
269:                 ) {
270:                     
271:                     _settlePaymentInFull(
272:                         item.token,
273:                         paymentAmount,
274:                         item.settleTo,
275:                         lender,
276:                         renter
277:                     );
278:                 } else {
279:                     revert Errors.Shared_OrderTypeNotSupported(uint8(orderType)); // <= FOUND
280:                 }
281:             }
282:         }

```


*GitHub* : [231](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L231-L279)

```solidity
475:        for (uint256 i = 0; i < hooks.length; ++i) { // <= FOUND
476:             
477:             target = hooks[i].target;
478: 
479:             
480:             if (!STORE.hookOnStart(target)) {
481:                 revert Errors.Shared_DisabledHook(target);
482:             }
483: 
484:             
485:             itemIndex = hooks[i].itemIndex;
486: 
487:             
488:             offer = offerItems[itemIndex];
489: 
490:             
491:             if (!offer.isRental()) {
492:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
493:             }
494: 
495:             
496:             try
497:                 IHook(target).onStart(
498:                     rentalWallet,
499:                     offer.token,
500:                     offer.identifier,
501:                     offer.amount,
502:                     hooks[i].extraData
503:                 )
504:             {} catch Error(string memory revertReason) {
505:                 
506:                 revert Errors.Shared_HookFailString(revertReason);
507:             } catch Panic(uint256 errorCode) { // <= FOUND
508:                 
509:                 string memory stringErrorCode = LibString.toString(errorCode);
510: 
511:                 
512:                 revert Errors.Shared_HookFailString(
513:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
514:                 );
515:             } catch (bytes memory revertData) {
516:                 
517:                 revert Errors.Shared_HookFailBytes(revertData);
518:             }
519:         }

```


*GitHub* : [475](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L475-L507)

```solidity
205:        for (uint256 i = 0; i < hooks.length; ++i) { // <= FOUND
206:             
207:             target = hooks[i].target;
208: 
209:             
210:             if (!STORE.hookOnStop(target)) {
211:                 revert Errors.Shared_DisabledHook(target);
212:             }
213: 
214:             
215:             itemIndex = hooks[i].itemIndex;
216: 
217:             
218:             item = rentalItems[itemIndex];
219: 
220:             
221:             if (!item.isRental()) {
222:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
223:             }
224: 
225:             
226:             try
227:                 IHook(target).onStop(
228:                     rentalWallet,
229:                     item.token,
230:                     item.identifier,
231:                     item.amount,
232:                     hooks[i].extraData
233:                 )
234:             {} catch Error(string memory revertReason) {
235:                 
236:                 revert Errors.Shared_HookFailString(revertReason);
237:             } catch Panic(uint256 errorCode) { // <= FOUND
238:                 
239:                 string memory stringErrorCode = LibString.toString(errorCode);
240: 
241:                 
242:                 revert Errors.Shared_HookFailString(
243:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
244:                 );
245:             } catch (bytes memory revertData) {
246:                 
247:                 revert Errors.Shared_HookFailBytes(revertData);
248:             }
249:         }

```


*GitHub* : [205](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L205-L237)

```solidity
324:        for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND
325:             
326:             _validateRentalCanBeStoped(
327:                 orders[i].orderType,
328:                 orders[i].endTimestamp,
329:                 orders[i].lender
330:             );
331: 
332:             
333:             for (uint256 j = 0; j < orders[i].items.length; ++j) {
334:                 
335:                 if (orders[i].items[j].isRental()) {
336:                     _insert(
337:                         rentalAssetUpdates,
338:                         orders[i].items[j].toRentalId(orders[i].rentalWallet),
339:                         orders[i].items[j].amount
340:                     );
341:                 }
342:             }
343: 
344:             
345:             orderHashes[i] = _deriveRentalOrderHash(orders[i]);
346: 
347:             
348:             if (orders[i].hooks.length > 0) {
349:                 _removeHooks(orders[i].hooks, orders[i].items, orders[i].rentalWallet);
350:             }
351: 
352:             
353:             _reclaimRentedItems(orders[i]);
354: 
355:             
356:             _emitRentalOrderStopped(orderHashes[i], msg.sender);
357:         }

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L324-L324)

```solidity
592:        for (uint256 i; i < depcLength; ++i) { // <= FOUND
593:             
594:             Keycode keycode = dependencies[i];
595:             Policy[] storage dependents = moduleDependents[keycode];
596: 
597:             
598:             uint256 origIndex = getDependentIndex[keycode][policy_];
599: 
600:             
601:             Policy lastPolicy = dependents[dependents.length - 1];
602: 
603:             
604:             dependents[origIndex] = lastPolicy;
605: 
606:             
607:             
608:             dependents.pop();
609: 
610:             
611:             getDependentIndex[keycode][lastPolicy] = origIndex;
612: 
613:             
614:             delete getDependentIndex[keycode][policy_];
615:         }

```


*GitHub* : [592](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L592-L592)
### [G-48]<a name="g-48"></a> The use of a logical AND in place of double if is slightly less gas efficient in instances where there isn't a corresponding else statement for the given if statement
Using a double if statement instead of logical AND (&&) can provide similar short-circuiting behavior whereas double if is slightly more efficient.

*There are 6 instance(s) of this issue:*

```solidity
115: 
116:         
117:         
118:         
119:         
120:         
121:         
122:         
123:         
124:         
125:         if (!success || (data.length != 0 && !abi.decode(data, (bool)))) { // <= FOUND

```


*GitHub* : [125](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L125-L125)

```solidity
255: 
256:                 
257:                 if (orderType.isPayOrder() && !isRentalOver) { // <= FOUND

```


*GitHub* : [257](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L257-L257)

```solidity
267:                 
268:                 else if (
269:                     (orderType.isPayOrder() && isRentalOver) || orderType.isBaseOrder() // <= FOUND
270:                 ) {

```


*GitHub* : [269](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L269-L269)

```solidity
324:         
325:         
326:         if (operation == Enum.Operation.DelegateCall && !STORE.whitelistedDelegates(to)) { // <= FOUND

```


*GitHub* : [326](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L326-L326)

```solidity
338: 
339:         
340:         if (hook != address(0) && isActive) { // <= FOUND

```


*GitHub* : [340](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L340-L340)

```solidity
148:             
149:             
150:             if (!isLender && (!hasExpired)) { // <= FOUND

```


*GitHub* : [150](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L150-L150)
### [G-49]<a name="g-49"></a> Calling .length in a for loop wastes gas
Rather than calling .length for an array in a for loop declaration, it is far more gas efficient to cache this length before and use that instead. This will prevent the array length from being called every loop iteration

*There are 12 instance(s) of this issue:*

```solidity
599: for (uint256 i = 0; i < items.length; ++i)  // <= FOUND

```


*GitHub* : [599](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L599-L599)

```solidity
324: for (uint256 i = 0; i < orders.length; ++i)  // <= FOUND

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L324-L324)

```solidity
197: for (uint256 i = 0; i < rentalAssetUpdates.length; ++i)  // <= FOUND

```


*GitHub* : [197](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L197-L197)

```solidity
249: for (uint256 i = 0; i < orderHashes.length; ++i)  // <= FOUND

```


*GitHub* : [249](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L249-L249)

```solidity
170: for (uint256 i = 0; i < order.items.length; ++i)  // <= FOUND

```


*GitHub* : [170](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L170-L170)

```solidity
225: for (uint256 i = 0; i < metadata.hooks.length; ++i)  // <= FOUND

```


*GitHub* : [225](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L225-L225)

```solidity
209: for (uint256 i; i < offers.length; ++i)  // <= FOUND

```


*GitHub* : [209](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L209-L209)

```solidity
337: for (uint256 i; i < considerations.length; ++i)  // <= FOUND

```


*GitHub* : [337](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L337-L337)

```solidity
475: for (uint256 i = 0; i < hooks.length; ++i)  // <= FOUND

```


*GitHub* : [475](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L475-L475)

```solidity
567: for (uint256 i; i < items.length; ++i)  // <= FOUND

```


*GitHub* : [567](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L567-L567)

```solidity
695: for (uint256 i = 0; i < executions.length; ++i)  // <= FOUND

```


*GitHub* : [695](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L695-L695)

```solidity
276: for (uint256 i; i < order.items.length; ++i)  // <= FOUND

```


*GitHub* : [276](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L276-L276)
### [G-50]<a name="g-50"></a> Internal functions only used once can be inlined so save gas
If a internal function is only used once it doesn't make sense to modularise it unless the function which does call the function would be overly long and complex otherwise

*There are 32 instance(s) of this issue:*

```solidity
88:     function _calculateFee(uint256 amount) internal view returns (uint256)  // <= FOUND

```


*GitHub* : [88](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L88-L88)

```solidity
132:     function _calculatePaymentProRata( // <= FOUND
133:         uint256 amount,
134:         uint256 elapsedTime,
135:         uint256 totalTime
136:     ) internal pure returns (uint256 renterAmount, uint256 lenderAmount) 

```


*GitHub* : [132](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L132-L132)

```solidity
159:     function _settlePaymentProRata( // <= FOUND
160:         address token,
161:         uint256 amount,
162:         address lender,
163:         address renter,
164:         uint256 elapsedTime,
165:         uint256 totalTime
166:     ) internal 

```


*GitHub* : [159](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L159-L159)

```solidity
190:     function _settlePaymentInFull( // <= FOUND
191:         address token,
192:         uint256 amount,
193:         SettleTo settleTo,
194:         address lender,
195:         address renter
196:     ) internal 

```


*GitHub* : [190](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L190-L190)

```solidity
292:     function _decreaseDeposit(address token, uint256 amount) internal  // <= FOUND

```


*GitHub* : [292](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L292-L292)

```solidity
304:     function _increaseDeposit(address token, uint256 amount) internal  // <= FOUND

```


*GitHub* : [304](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L304-L304)

```solidity
76:     function _validateFulfiller( // <= FOUND
77:         address intendedFulfiller,
78:         address actualFulfiller
79:     ) internal pure 

```


*GitHub* : [76](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L76-L76)

```solidity
94:     function _validateProtocolSignatureExpiration(uint256 expiration) internal view  // <= FOUND

```


*GitHub* : [94](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L94-L94)

```solidity
107:     function _recoverSignerFromPayload( // <= FOUND
108:         bytes32 payloadHash,
109:         bytes memory signature
110:     ) internal view returns (address) 

```


*GitHub* : [107](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L107-L107)

```solidity
125:     function _deriveItemHash(Item memory item) internal view returns (bytes32)  // <= FOUND

```


*GitHub* : [125](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L125-L125)

```solidity
204:     function _deriveOrderFulfillmentHash( // <= FOUND
205:         OrderFulfillment memory fulfillment
206:     ) internal view returns (bytes32) 

```


*GitHub* : [204](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L204-L204)

```solidity
273:     function _deriveDomainSeparator( // <= FOUND
274:         bytes32 _eip712DomainTypeHash,
275:         bytes32 _nameHash,
276:         bytes32 _versionHash
277:     ) internal view virtual returns (bytes32) 

```


*GitHub* : [273](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L273-L273)

```solidity
298:     function _deriveTypehashes() // <= FOUND
299:         internal
300:         view
301:         returns (
302:             bytes32 nameHash,
303:             bytes32 versionHash,
304:             bytes32 eip712DomainTypehash,
305:             bytes32 domainSeparator
306:         )
307:     

```


*GitHub* : [298](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L298-L298)

```solidity
339:     function _deriveRentalTypehashes() // <= FOUND
340:         internal
341:         pure
342:         returns (
343:             bytes32 itemTypeHash,
344:             bytes32 hookTypeHash,
345:             bytes32 rentalOrderTypeHash,
346:             bytes32 orderFulfillmentTypeHash,
347:             bytes32 orderMetadataTypeHash,
348:             bytes32 rentPayloadTypeHash
349:         )
350:     

```


*GitHub* : [339](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L339-L339)

```solidity
165:     function _emitRentalOrderStarted( // <= FOUND
166:         RentalOrder memory order,
167:         bytes32 orderHash,
168:         bytes memory extraData
169:     ) internal 

```


*GitHub* : [165](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L165-L165)

```solidity
195:     function _processBaseOrderOffer( // <= FOUND
196:         Item[] memory rentalItems,
197:         SpentItem[] memory offers,
198:         uint256 startIndex
199:     ) internal pure 

```


*GitHub* : [195](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L195-L195)

```solidity
247:     function _processPayOrderOffer( // <= FOUND
248:         Item[] memory rentalItems,
249:         SpentItem[] memory offers,
250:         uint256 startIndex
251:     ) internal pure 

```


*GitHub* : [247](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L247-L247)

```solidity
326:     function _processBaseOrderConsideration( // <= FOUND
327:         Item[] memory rentalItems,
328:         ReceivedItem[] memory considerations,
329:         uint256 startIndex
330:     ) internal pure 

```


*GitHub* : [326](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L326-L326)

```solidity
367:     function _processPayeeOrderConsideration( // <= FOUND
368:         ReceivedItem[] memory considerations
369:     ) internal pure 

```


*GitHub* : [367](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L367-L367)

```solidity
411:     function _convertToItems( // <= FOUND
412:         SpentItem[] memory offers,
413:         ReceivedItem[] memory considerations,
414:         OrderType orderType
415:     ) internal pure returns (Item[] memory items) 

```


*GitHub* : [411](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L411-L411)

```solidity
464:     function _addHooks( // <= FOUND
465:         Hook[] memory hooks,
466:         SpentItem[] memory offerItems,
467:         address rentalWallet
468:     ) internal 

```


*GitHub* : [464](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L464-L464)

```solidity
530:     function _rentFromZone( // <= FOUND
531:         RentPayload memory payload,
532:         SeaportPayload memory seaportPayload
533:     ) internal 

```


*GitHub* : [530](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L530-L530)

```solidity
626:     function _isValidOrderMetadata( // <= FOUND
627:         OrderMetadata memory metadata,
628:         bytes32 zoneHash
629:     ) internal view 

```


*GitHub* : [626](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L626-L626)

```solidity
647:     function _isValidSafeOwner(address owner, address safe) internal view  // <= FOUND

```


*GitHub* : [647](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L647-L647)

```solidity
691:     function _executionInvariantChecks( // <= FOUND
692:         ReceivedItem[] memory executions,
693:         address expectedRentalSafe
694:     ) internal view 

```


*GitHub* : [691](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L691-L691)

```solidity
356:     function _installModule(Module newModule_) internal  // <= FOUND

```


*GitHub* : [356](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L356-L356)

```solidity
383:     function _upgradeModule(Module newModule_) internal  // <= FOUND

```


*GitHub* : [383](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L383-L383)

```solidity
418:     function _activatePolicy(Policy policy_) internal  // <= FOUND

```


*GitHub* : [418](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L418-L418)

```solidity
457:     function _deactivatePolicy(Policy policy_) internal  // <= FOUND

```


*GitHub* : [457](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L457-L457)

```solidity
508:     function _migrateKernel(Kernel newKernel_) internal  // <= FOUND

```


*GitHub* : [508](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L508-L508)

```solidity
540:     function _reconfigurePolicies(Keycode keycode_) internal  // <= FOUND

```


*GitHub* : [540](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L540-L540)

```solidity
586:     function _pruneFromDependents(Policy policy_) internal  // <= FOUND

```


*GitHub* : [586](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L586-L586)
### [G-51]<a name="g-51"></a> Constructors can be marked as payable to save deployment gas

*There are 10 instance(s) of this issue:*

```solidity
79:     constructor(Kernel kernel_) Module(kernel_) {}

```


*GitHub* : [79](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L79-L79)

```solidity
22:     constructor() {
23:         original = address(this);
24:     }

```


*GitHub* : [22](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L22-L22)

```solidity
44:     constructor() {
45:         
46:         (
47:             _NAME_HASH,
48:             _VERSION_HASH,
49:             _EIP_712_DOMAIN_TYPEHASH,
50:             _DOMAIN_SEPARATOR
51:         ) = _deriveTypehashes();
52: 
53:         
54:         (
55:             _ITEM_TYPEHASH,
56:             _HOOK_TYPEHASH,
57:             _RENTAL_ORDER_TYPEHASH,
58:             _ORDER_FULFILLMENT_TYPEHASH,
59:             _ORDER_METADATA_TYPEHASH,
60:             _RENT_PAYLOAD_TYPEHASH
61:         ) = _deriveRentalTypehashes();
62: 
63:         
64:         _CHAIN_ID = block.chainid;
65:     }

```


*GitHub* : [44](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L44-L44)

```solidity
29:     constructor(Kernel kernel_) Policy(kernel_) {}

```


*GitHub* : [29](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L29-L29)

```solidity
61:     constructor(Kernel kernel_) Policy(kernel_) Signer() Zone() {}

```


*GitHub* : [61](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L61-L61)

```solidity
49:     constructor(
50:         Kernel kernel_,
51:         Stop stopPolicy_,
52:         Guard guardPolicy_,
53:         TokenCallbackHandler fallbackHandler_,
54:         SafeProxyFactory safeProxyFactory_,
55:         SafeL2 safeSingleton_
56:     ) Policy(kernel_) {
57:         stopPolicy = stopPolicy_;
58:         guardPolicy = guardPolicy_;
59:         fallbackHandler = fallbackHandler_;
60:         safeProxyFactory = safeProxyFactory_;
61:         safeSingleton = safeSingleton_;
62:     }

```


*GitHub* : [49](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L49-L49)

```solidity
52:     constructor(Kernel kernel_) Policy(kernel_) Signer() Reclaimer() {}

```


*GitHub* : [52](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L52-L52)

```solidity
33:     constructor(Kernel kernel_) {
34:         kernel = kernel_;
35:     }

```


*GitHub* : [33](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L33-L33)

```solidity
71:     constructor(Kernel kernel_) KernelAdapter(kernel_) {}

```


*GitHub* : [71](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L71-L71)

```solidity
242:     constructor(address _executor, address _admin) {
243:         executor = _executor;
244:         admin = _admin;
245:     }

```


*GitHub* : [242](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L242-L242)
### [G-52]<a name="g-52"></a> Use assembly scratch space to build calldata for external calls
Using Solidity's assembly scratch space for constructing calldata in external calls with one or two arguments can be a gas-efficient approach. This method leverages the designated memory area (the first 64 bytes of memory) for temporary data storage during assembly operations. By directly writing arguments into this scratch space, it eliminates the need for additional memory allocation typically required for calldata preparation. This technique can lead to notable gas savings, especially in high-frequency or gas-sensitive operations. However, it requires careful implementation to avoid data corruption and should be used with a thorough understanding of low-level EVM operations and memory handling. Proper testing and validation are crucial when employing such optimizations.

*There are 101 instance(s) of this issue:*

```solidity
411: 
412:         
413:         emit Events.FeeTaken(token, skimmedBalance); // <= FOUND

```


*GitHub* : [411](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L411-L413)

```solidity
94: 
95:             
96:             if (item.itemType == ItemType.ERC721) // <= FOUND
97:                 _transferERC721(item, rentalOrder.lender); // <= FOUND

```


*GitHub* : [94](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L94-L97)

```solidity
98: 
99:             
100:             if (item.itemType == ItemType.ERC1155) // <= FOUND
101:                 _transferERC1155(item, rentalOrder.lender); // <= FOUND

```


*GitHub* : [98](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L98-L101)

```solidity
82:             revert Errors.SignerPackage_UnauthorizedFulfiller( // <= FOUND
83:                 actualFulfiller, // <= FOUND
84:                 intendedFulfiller
85:             );

```


*GitHub* : [82](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L82-L83)

```solidity
97:             revert Errors.SignerPackage_SignatureExpired(block.timestamp, expiration); // <= FOUND

```


*GitHub* : [97](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L97-L97)

```solidity
103:         STORE.toggleWhitelistDelegate(delegate, isEnabled); // <= FOUND

```


*GitHub* : [103](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L103-L103)

```solidity
117:         STORE.toggleWhitelistExtension(extension, isEnabled); // <= FOUND

```


*GitHub* : [117](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L117-L117)

```solidity
165:         ESCRW.skim(token, to); // <= FOUND

```


*GitHub* : [165](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L165-L165)

```solidity
312:             revert Errors.CreatePolicy_ItemCountZero(totalRentals, totalPayments); // <= FOUND

```


*GitHub* : [312](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L312-L312)

```solidity
512: 
513:                 
514:                 revert Errors.Shared_HookFailString( // <= FOUND
515:                     string.concat("Hook reverted: Panic code ", stringErrorCode) // <= FOUND
516:                 );

```


*GitHub* : [512](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L512-L515)

```solidity
570:                     
571:                     _insert( // <= FOUND
572:                         rentalAssetUpdates, // <= FOUND
573:                         items[i].toRentalId(payload.fulfillment.recipient), // <= FOUND
574:                         items[i].amount // <= FOUND
575:                     );

```


*GitHub* : [570](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L570-L574)

```solidity
595: 
596:             
597:             STORE.addRentals(orderHash, _convertToStatic(rentalAssetUpdates)); // <= FOUND

```


*GitHub* : [595](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L595-L597)

```solidity
601:                     ESCRW.increaseDeposit(items[i].token, items[i].amount); // <= FOUND

```


*GitHub* : [601](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L601-L601)

```solidity
655:             revert Errors.CreatePolicy_InvalidSafeOwner(owner, safe); // <= FOUND

```


*GitHub* : [655](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L655-L655)

```solidity
766: 
767:         
768:         if (!kernel.hasRole(signer, toRole("CREATE_SIGNER"))) { // <= FOUND

```


*GitHub* : [766](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L766-L768)

```solidity
144:             revert Errors.FactoryPolicy_InvalidSafeThreshold(threshold, owners.length); // <= FOUND

```


*GitHub* : [144](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L144-L144)

```solidity
512: 
513:             
514:             revert Errors.Shared_HookFailString( // <= FOUND
515:                 string.concat("Hook reverted: Panic code ", stringErrorCode) // <= FOUND
516:             );

```


*GitHub* : [512](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L512-L515)

```solidity
363:         STORE.updateHookPath(to, hook); // <= FOUND

```


*GitHub* : [363](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L363-L363)

```solidity
377:         STORE.updateHookStatus(hook, bitmap); // <= FOUND

```


*GitHub* : [377](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L377-L377)

```solidity
113:         
114:         emit Events.RentalOrderStopped(seaportOrderHash, stopper); // <= FOUND

```


*GitHub* : [113](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L113-L114)

```solidity
141:                 revert Errors.StopPolicy_CannotStopOrder(block.timestamp, msg.sender); // <= FOUND

```


*GitHub* : [141](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L141-L141)

```solidity
279:                 
280:                 _insert( // <= FOUND
281:                     rentalAssetUpdates, // <= FOUND
282:                     order.items[i].toRentalId(order.rentalWallet), // <= FOUND
283:                     order.items[i].amount // <= FOUND
284:                 );

```


*GitHub* : [279](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L279-L283)

```solidity
299: 
300:         
301:         STORE.removeRentals( // <= FOUND
302:             _deriveRentalOrderHash(order), // <= FOUND
303:             _convertToStatic(rentalAssetUpdates) // <= FOUND
304:         );

```


*GitHub* : [299](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L299-L303)

```solidity
336:                     _insert( // <= FOUND
337:                         rentalAssetUpdates, // <= FOUND
338:                         orders[i].items[j].toRentalId(orders[i].rentalWallet), // <= FOUND
339:                         orders[i].items[j].amount // <= FOUND
340:                     );

```


*GitHub* : [336](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L336-L339)

```solidity
363: 
364:         
365:         STORE.removeRentalsBatch(orderHashes, _convertToStatic(rentalAssetUpdates)); // <= FOUND

```


*GitHub* : [363](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L363-L365)

```solidity
38:             revert Errors.Create2Deployer_UnauthorizedSender(msg.sender, salt); // <= FOUND

```


*GitHub* : [38](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L38-L38)

```solidity
46:             revert Errors.Create2Deployer_AlreadyDeployed(targetDeploymentAddress, salt); // <= FOUND

```


*GitHub* : [46](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L46-L46)

```solidity
68:             revert Errors.Create2Deployer_MismatchedDeploymentAddress( // <= FOUND
69:                 targetDeploymentAddress, // <= FOUND
70:                 deploymentAddress
71:             );

```


*GitHub* : [68](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L68-L69)

```solidity
132:         if (!kernel.hasRole(msg.sender, role)) { // <= FOUND

```


*GitHub* : [132](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L132-L132)

```solidity
301: 
302:         emit Events.ActionExecuted(action_, target_); // <= FOUND

```


*GitHub* : [301](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L301-L302)

```solidity
312:         
313:         if (hasRole[addr_][role_]) // <= FOUND
314:             revert Errors.Kernel_AddressAlreadyHasRole(addr_, role_); // <= FOUND

```


*GitHub* : [312](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L312-L314)

```solidity
324: 
325:         emit Events.RoleGranted(role_, addr_); // <= FOUND

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L324-L325)

```solidity
338: 
339:         
340:         if (!hasRole[addr_][role_]) // <= FOUND
341:             revert Errors.Kernel_AddressDoesNotHaveRole(addr_, role_); // <= FOUND

```


*GitHub* : [338](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L338-L341)

```solidity
344: 
345:         emit Events.RoleRevoked(role_, addr_); // <= FOUND

```


*GitHub* : [344](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L344-L345)

```solidity
76:         return Keycode.wrap("ESCRW"); // <= FOUND

```


*GitHub* : [76](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L76-L76)

```solidity
279:                     revert Errors.Shared_OrderTypeNotSupported(uint8(orderType)); // <= FOUND

```


*GitHub* : [279](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L279-L279)

```solidity
402: 
403:         
404:         uint256 trueBalance = IERC20(token).balanceOf(address(this)); // <= FOUND

```


*GitHub* : [402](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L402-L404)

```solidity
104:         return Keycode.wrap("STORE"); // <= FOUND

```


*GitHub* : [104](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L104-L104)

```solidity
222:             revert Errors.StorageModule_OrderDoesNotExist(orderHash); // <= FOUND

```


*GitHub* : [222](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L222-L222)

```solidity
252:                 revert Errors.StorageModule_OrderDoesNotExist(orderHashes[i]); // <= FOUND

```


*GitHub* : [252](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L252-L252)

```solidity
296:         
297:         if (to.code.length == 0) revert Errors.StorageModule_NotContract(to); // <= FOUND

```


*GitHub* : [296](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L296-L297)

```solidity
299: 
300:         
301:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook); // <= FOUND

```


*GitHub* : [299](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L299-L301)

```solidity
299:         
300:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook); // <= FOUND

```


*GitHub* : [299](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L299-L300)

```solidity
38:         
39:         bytes32 _rentalId = RentalId.unwrap(rentalId); // <= FOUND

```


*GitHub* : [38](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L38-L39)

```solidity
81:             revert Errors.ReclaimerPackage_OnlyRentalSafeAllowed( // <= FOUND
82:                 rentalOrder.rentalWallet // <= FOUND
83:             );

```


*GitHub* : [81](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L81-L82)

```solidity
112:         
113:         bytes32 digest = _DOMAIN_SEPARATOR.toTypedDataHash(payloadHash); // <= FOUND

```


*GitHub* : [112](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L112-L113)

```solidity
115: 
116:         
117:         return digest.recover(signature); // <= FOUND

```


*GitHub* : [115](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L115-L117)

```solidity
127:         STORE.upgrade(newImplementation); // <= FOUND

```


*GitHub* : [127](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L127-L127)

```solidity
147:         ESCRW.upgrade(newImplementation); // <= FOUND

```


*GitHub* : [147](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L147-L147)

```solidity
174:         ESCRW.setFee(feeNumerator); // <= FOUND

```


*GitHub* : [174](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L174-L174)

```solidity
223:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(offer.itemType); // <= FOUND

```


*GitHub* : [223](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L223-L223)

```solidity
343:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported( // <= FOUND
344:                     consideration.itemType // <= FOUND
345:                 );

```


*GitHub* : [343](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L343-L344)

```solidity
434:                 revert Errors.CreatePolicy_ConsiderationCountNonZero( // <= FOUND
435:                     considerations.length // <= FOUND
436:                 );

```


*GitHub* : [434](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L434-L435)

```solidity
443:                 revert Errors.CreatePolicy_OfferCountNonZero(offers.length); // <= FOUND

```


*GitHub* : [443](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L443-L443)

```solidity
451:             revert Errors.Shared_OrderTypeNotSupported(uint8(orderType)); // <= FOUND

```


*GitHub* : [451](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L451-L451)

```solidity
480: 
481:             
482:             if (!STORE.hookOnStart(target)) { // <= FOUND

```


*GitHub* : [480](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L480-L482)

```solidity
481:                 revert Errors.Shared_DisabledHook(target); // <= FOUND

```


*GitHub* : [481](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L481-L481)

```solidity
492:                 revert Errors.Shared_NonRentalHookItem(itemIndex); // <= FOUND

```


*GitHub* : [492](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L492-L492)

```solidity
506:                 
507:                 revert Errors.Shared_HookFailString(revertReason); // <= FOUND

```


*GitHub* : [506](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L506-L507)

```solidity
509:                 
510:                 string memory stringErrorCode = LibString.toString(errorCode); // <= FOUND

```


*GitHub* : [509](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L509-L510)

```solidity
517:                 
518:                 revert Errors.Shared_HookFailBytes(revertData); // <= FOUND

```


*GitHub* : [517](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L517-L518)

```solidity
649:         
650:         if (STORE.deployedSafes(safe) == 0) { // <= FOUND

```


*GitHub* : [649](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L649-L650)

```solidity
650:             revert Errors.CreatePolicy_InvalidRentalSafe(safe); // <= FOUND

```


*GitHub* : [650](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L650-L650)

```solidity
654: 
655:         
656:         if (!ISafe(safe).isOwner(owner)) { // <= FOUND

```


*GitHub* : [654](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L654-L656)

```solidity
709:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported( // <= FOUND
710:                     execution.itemType // <= FOUND
711:                 );

```


*GitHub* : [709](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L709-L710)

```solidity
124:         
125:         ISafe(address(this)).enableModule(_stopPolicy); // <= FOUND

```


*GitHub* : [124](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L124-L125)

```solidity
127: 
128:         
129:         ISafe(address(this)).setGuard(_guardPolicy); // <= FOUND

```


*GitHub* : [127](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L127-L129)

```solidity
189: 
190:         
191:         STORE.addRentalSafe(safe); // <= FOUND

```


*GitHub* : [189](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L189-L191)

```solidity
134:             revert Errors.GuardPolicy_UnauthorizedSelector(selector); // <= FOUND

```


*GitHub* : [134](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L134-L134)

```solidity
145:         
146:         if (!STORE.whitelistedExtensions(extension)) { // <= FOUND

```


*GitHub* : [145](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L145-L146)

```solidity
146:             revert Errors.GuardPolicy_UnauthorizedExtension(extension); // <= FOUND

```


*GitHub* : [146](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L146-L146)

```solidity
506:             
507:             revert Errors.Shared_HookFailString(revertReason); // <= FOUND

```


*GitHub* : [506](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L506-L507)

```solidity
509:             
510:             string memory stringErrorCode = LibString.toString(errorCode); // <= FOUND

```


*GitHub* : [509](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L509-L510)

```solidity
517:             
518:             revert Errors.Shared_HookFailBytes(revertData); // <= FOUND

```


*GitHub* : [517](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L517-L518)

```solidity
271:                 revert Errors.GuardPolicy_UnauthorizedSelector( // <= FOUND
272:                     shared_set_approval_for_all_selector
273:                 );

```


*GitHub* : [271](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L271-L271)

```solidity
281:                 revert Errors.GuardPolicy_UnauthorizedSelector( // <= FOUND
282:                     e1155_safe_batch_transfer_from_selector
283:                 );

```


*GitHub* : [281](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L281-L281)

```solidity
288:                 revert Errors.GuardPolicy_UnauthorizedSelector( // <= FOUND
289:                     gnosis_safe_set_guard_selector
290:                 );

```


*GitHub* : [288](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L288-L288)

```solidity
324:         
325:         
326:         if (operation == Enum.Operation.DelegateCall && !STORE.whitelistedDelegates(to)) { // <= FOUND

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L324-L326)

```solidity
325:             revert Errors.GuardPolicy_UnauthorizedDelegateCall(to); // <= FOUND

```


*GitHub* : [325](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L325-L325)

```solidity
334: 
335:         
336:         address hook = STORE.contractToHook(to); // <= FOUND

```


*GitHub* : [334](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L334-L336)

```solidity
335:         bool isActive = STORE.hookOnTransaction(hook); // <= FOUND

```


*GitHub* : [335](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L335-L335)

```solidity
210: 
211:             
212:             if (!STORE.hookOnStop(target)) { // <= FOUND

```


*GitHub* : [210](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L210-L212)

```solidity
296: 
297:         
298:         ESCRW.settlePayment(order); // <= FOUND

```


*GitHub* : [296](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L296-L298)

```solidity
360: 
361:         
362:         ESCRW.settlePaymentBatch(orders); // <= FOUND

```


*GitHub* : [360](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L360-L362)

```solidity
41:         if (msg.sender != address(kernel)) // <= FOUND
42:             revert Errors.KernelAdapter_OnlyKernel(msg.sender); // <= FOUND

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L41-L42)

```solidity
79:             revert Errors.Module_PolicyNotAuthorized(msg.sender); // <= FOUND

```


*GitHub* : [79](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L79-L79)

```solidity
133:             revert Errors.Policy_OnlyRole(role); // <= FOUND

```


*GitHub* : [133](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L133-L133)

```solidity
181:         address moduleForKeycode = address(kernel.getModuleForKeycode(keycode_)); // <= FOUND

```


*GitHub* : [181](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L181-L181)

```solidity
255:         if (msg.sender != executor) revert Errors.Kernel_OnlyExecutor(msg.sender); // <= FOUND

```


*GitHub* : [255](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L255-L255)

```solidity
263:         if (msg.sender != admin) revert Errors.Kernel_OnlyAdmin(msg.sender); // <= FOUND

```


*GitHub* : [263](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L263-L263)

```solidity
335:         
336:         if (!isRole[role_]) revert Errors.Kernel_RoleDoesNotExist(role_); // <= FOUND

```


*GitHub* : [335](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L335-L336)

```solidity
362:             revert Errors.Kernel_ModuleAlreadyInstalled(keycode); // <= FOUND

```


*GitHub* : [362](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L362-L362)

```solidity
372: 
373:         
374:         allKeycodes.push(keycode); // <= FOUND

```


*GitHub* : [372](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L372-L374)

```solidity
393:             revert Errors.Kernel_InvalidModuleUpgrade(keycode); // <= FOUND

```


*GitHub* : [393](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L393-L393)

```solidity
428: 
429:         
430:         activePolicies.push(policy_); // <= FOUND

```


*GitHub* : [428](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L428-L430)

```solidity
442: 
443:             
444:             moduleDependents[keycode].push(policy_); // <= FOUND

```


*GitHub* : [442](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L442-L444)

```solidity
449: 
450:         
451:         policy_.setActiveStatus(true); // <= FOUND

```


*GitHub* : [449](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L449-L451)

```solidity
489: 
490:         
491:         policy_.setActiveStatus(false); // <= FOUND

```


*GitHub* : [489](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L489-L491)

```solidity
516:             
517:             module.changeKernel(newKernel_); // <= FOUND

```


*GitHub* : [516](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L516-L517)

```solidity
526: 
527:             
528:             policy.setActiveStatus(false); // <= FOUND

```


*GitHub* : [526](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L526-L528)

```solidity
529: 
530:             
531:             policy.changeKernel(newKernel_); // <= FOUND

```


*GitHub* : [529](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L529-L531)
### [G-53]<a name="g-53"></a> Use assembly scratch space to build calldata for event emits
Utilizing Solidity's assembly scratch space to build calldata for emitting events with just one or two arguments can optimize gas usage. The scratch space, a designated area in the first 64 bytes of memory, is ideal for temporary storage during assembly-level operations. By directly writing the event arguments into this area, developers can bypass the standard memory allocation process required for event emission. This approach results in gas savings, particularly for contracts where events are frequently emitted. However, such low-level optimization requires a deep understanding of Ethereum Virtual Machine (EVM) mechanics and careful coding to prevent data mishandling. Rigorous testing is essential to ensure the integrity and correct functionality of the contract.

*There are 5 instance(s) of this issue:*

```solidity
411: 
412:         
413:         emit Events.FeeTaken(token, skimmedBalance); // <= FOUND

```


*GitHub* : [411](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L411-L413)

```solidity
113:         
114:         emit Events.RentalOrderStopped(seaportOrderHash, stopper); // <= FOUND

```


*GitHub* : [113](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L113-L114)

```solidity
301: 
302:         emit Events.ActionExecuted(action_, target_); // <= FOUND

```


*GitHub* : [301](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L301-L302)

```solidity
324: 
325:         emit Events.RoleGranted(role_, addr_); // <= FOUND

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L324-L325)

```solidity
344: 
345:         emit Events.RoleRevoked(role_, addr_); // <= FOUND

```


*GitHub* : [344](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L344-L345)
### [G-54]<a name="g-54"></a> Consider using solady's "FixedPointMathLib"
Using Solady's "FixedPointMathLib" for multiplication or division operations in Solidity can lead to significant gas savings. This library is designed to optimize fixed-point arithmetic operations, which are common in financial calculations involving tokens or currencies. By implementing more efficient algorithms and assembly optimizations, "FixedPointMathLib" minimizes the computational resources required for these operations. For contracts that frequently perform such calculations, integrating this library can reduce transaction costs, thereby enhancing overall performance and cost-effectiveness. However, developers must ensure compatibility with their existing codebase and thoroughly test for accuracy and expected behavior to avoid any unintended consequences.

*There are 2 instance(s) of this issue:*

```solidity
90:         
91:         return (amount * fee) / 10000; // <= FOUND

```


*GitHub* : [91](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L91-L91)

```solidity
142: 
143:         
144:         
145:         renterAmount = ((numerator / totalTime) + 500) / 1000; // <= FOUND

```


*GitHub* : [145](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L145-L145)
### [G-55]<a name="g-55"></a> Same cast is done multiple times
Repeatedly casting the same variable to the same type within a function is redundant and can be optimized for better gas efficiency and code readability. Each unnecessary cast operation, while minor, adds to the gas cost and clutters the code. To optimize, the best practice is to perform the cast once and store the result in a temporary variable, which can then be used wherever needed in the function.

*There are 1 instance(s) of this issue:*

```solidity
138:     function deployRentalSafe(
139:         address[] calldata owners,
140:         uint256 threshold
141:     ) external returns (address safe) {
142:         
143:         if (threshold == 0 || threshold > owners.length) {
144:             revert Errors.FactoryPolicy_InvalidSafeThreshold(threshold, owners.length);
145:         }
146: 
147:         
148:         
149:         bytes memory data = abi.encodeCall(
150:             Factory.initializeRentalSafe,
151:             (address(stopPolicy), address(guardPolicy))
152:         );
153: 
154:         
155:         bytes memory initializerPayload = abi.encodeCall(
156:             ISafe.setup,
157:             (
158:                 
159:                 owners,
160:                 
161:                 threshold,
162:                 
163:                 address(this),
164:                 
165:                 data,
166:                 
167:                 address(fallbackHandler),
168:                 
169:                 address(0), // <= FOUND 'address(0)'
170:                 
171:                 0,
172:                 
173:                 payable(address(0)) // <= FOUND 'address(0)'
174:             )
175:         );
176: 
177:         
178:         
179:         
180:         safe = address(
181:             safeProxyFactory.createProxyWithNonce(
182:                 address(safeSingleton),
183:                 initializerPayload,
184:                 uint256(keccak256(abi.encode(STORE.totalSafes() + 1, block.chainid)))
185:             )
186:         );
187: 
188:         
189:         STORE.addRentalSafe(safe);
190: 
191:         
192:         emit Events.RentalSafeDeployment(safe, owners, threshold);
193:     }

```


*GitHub* : [138](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L138-L173)
### [G-56]<a name="g-56"></a> Assigning to structs can be more efficient
Rather defining the struct in a single line, it is more efficient to declare an empty struct and then assign each struct element individually. This can net quite a large gas saving of 130 per instance.

*There are 5 instance(s) of this issue:*

```solidity
195:     function _processBaseOrderOffer(
196:         Item[] memory rentalItems,
197:         SpentItem[] memory offers,
198:         uint256 startIndex
199:     ) internal pure {
200:         
201:         if (offers.length == 0) {
202:             revert Errors.CreatePolicy_OfferCountZero();
203:         }
204: 
205:         
206:         ItemType itemType;
207: 
208:         
209:         for (uint256 i; i < offers.length; ++i) {
210:             
211:             SpentItem memory offer = offers[i];
212: 
213:             
214:             if (offer.isERC721()) {
215:                 itemType = ItemType.ERC721;
216:             }
217:             
218:             else if (offer.isERC1155()) {
219:                 itemType = ItemType.ERC1155;
220:             }
221:             
222:             else {
223:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(offer.itemType);
224:             }
225: 
226:             
227:             
228:             rentalItems[i + startIndex] = Item({
229:                 itemType: itemType,
230:                 settleTo: SettleTo.LENDER,
231:                 token: offer.token,
232:                 amount: offer.amount,
233:                 identifier: offer.identifier
234:             });
235:         }
236:     }

```


*GitHub* : [195](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L195-L195)

```solidity
247:     function _processPayOrderOffer(
248:         Item[] memory rentalItems,
249:         SpentItem[] memory offers,
250:         uint256 startIndex
251:     ) internal pure {
252:         
253:         uint256 totalRentals;
254:         uint256 totalPayments;
255: 
256:         
257:         ItemType itemType;
258:         SettleTo settleTo;
259: 
260:         
261:         for (uint256 i; i < offers.length; ++i) {
262:             
263:             SpentItem memory offer = offers[i];
264: 
265:             
266:             if (offer.isERC721()) {
267:                 
268:                 
269:                 itemType = ItemType.ERC721;
270:                 settleTo = SettleTo.LENDER;
271: 
272:                 
273:                 totalRentals++;
274:             }
275:             
276:             else if (offer.isERC1155()) {
277:                 
278:                 
279:                 itemType = ItemType.ERC1155;
280:                 settleTo = SettleTo.LENDER;
281: 
282:                 
283:                 totalRentals++;
284:             }
285:             
286:             else if (offer.isERC20()) {
287:                 
288:                 
289:                 itemType = ItemType.ERC20;
290:                 settleTo = SettleTo.RENTER;
291: 
292:                 
293:                 totalPayments++;
294:             }
295:             
296:             else {
297:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(offer.itemType);
298:             }
299: 
300:             
301:             rentalItems[i + startIndex] = Item({
302:                 itemType: itemType,
303:                 settleTo: settleTo,
304:                 token: offer.token,
305:                 amount: offer.amount,
306:                 identifier: offer.identifier
307:             });
308:         }
309: 
310:         
311:         if (totalRentals == 0 || totalPayments == 0) {
312:             revert Errors.CreatePolicy_ItemCountZero(totalRentals, totalPayments);
313:         }
314:     }

```


*GitHub* : [247](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L247-L247)

```solidity
326:     function _processBaseOrderConsideration(
327:         Item[] memory rentalItems,
328:         ReceivedItem[] memory considerations,
329:         uint256 startIndex
330:     ) internal pure {
331:         
332:         if (considerations.length == 0) {
333:             revert Errors.CreatePolicy_ConsiderationCountZero();
334:         }
335: 
336:         
337:         for (uint256 i; i < considerations.length; ++i) {
338:             
339:             ReceivedItem memory consideration = considerations[i];
340: 
341:             
342:             if (!consideration.isERC20()) {
343:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
344:                     consideration.itemType
345:                 );
346:             }
347: 
348:             
349:             
350:             rentalItems[i + startIndex] = Item({
351:                 itemType: ItemType.ERC20,
352:                 settleTo: SettleTo.LENDER,
353:                 token: consideration.token,
354:                 amount: consideration.amount,
355:                 identifier: consideration.identifier
356:             });
357:         }
358:     }

```


*GitHub* : [326](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L326-L326)

```solidity
530:     function _rentFromZone(
531:         RentPayload memory payload,
532:         SeaportPayload memory seaportPayload
533:     ) internal {
534:         
535:         _isValidOrderMetadata(payload.metadata, seaportPayload.zoneHash);
536: 
537:         
538:         _isValidSafeOwner(seaportPayload.fulfiller, payload.fulfillment.recipient);
539: 
540:         
541:         _executionInvariantChecks(
542:             seaportPayload.totalExecutions,
543:             payload.fulfillment.recipient
544:         );
545: 
546:         
547:         
548:         Item[] memory items = _convertToItems(
549:             seaportPayload.offer,
550:             seaportPayload.consideration,
551:             payload.metadata.orderType
552:         );
553: 
554:         
555:         
556:         if (
557:             payload.metadata.orderType.isBaseOrder() ||
558:             payload.metadata.orderType.isPayOrder()
559:         ) {
560:             
561:             
562:             
563:             bytes memory rentalAssetUpdates = new bytes(0);
564: 
565:             
566:             
567:             for (uint256 i; i < items.length; ++i) {
568:                 if (items[i].isRental()) {
569:                     
570:                     _insert(
571:                         rentalAssetUpdates,
572:                         items[i].toRentalId(payload.fulfillment.recipient),
573:                         items[i].amount
574:                     );
575:                 }
576:             }
577: 
578:             
579:             RentalOrder memory order = RentalOrder({
580:                 seaportOrderHash: seaportPayload.orderHash,
581:                 items: items,
582:                 hooks: payload.metadata.hooks,
583:                 orderType: payload.metadata.orderType,
584:                 lender: seaportPayload.offerer,
585:                 renter: payload.intendedFulfiller,
586:                 rentalWallet: payload.fulfillment.recipient,
587:                 startTimestamp: block.timestamp,
588:                 endTimestamp: block.timestamp + payload.metadata.rentDuration
589:             });
590: 
591:             
592:             bytes32 orderHash = _deriveRentalOrderHash(order);
593: 
594:             
595:             STORE.addRentals(orderHash, _convertToStatic(rentalAssetUpdates));
596: 
597:             
598:             
599:             for (uint256 i = 0; i < items.length; ++i) {
600:                 if (items[i].isERC20()) {
601:                     ESCRW.increaseDeposit(items[i].token, items[i].amount);
602:                 }
603:             }
604: 
605:             
606:             if (payload.metadata.hooks.length > 0) {
607:                 _addHooks(
608:                     payload.metadata.hooks,
609:                     seaportPayload.offer,
610:                     payload.fulfillment.recipient
611:                 );
612:             }
613: 
614:             
615:             _emitRentalOrderStarted(order, orderHash, payload.metadata.emittedExtraData);
616:         }
617:     }

```


*GitHub* : [530](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L530-L530)

```solidity
733:     function validateOrder(
734:         ZoneParameters calldata zoneParams
735:     ) external override onlyRole("SEAPORT") returns (bytes4 validOrderMagicValue) {
736:         
737:         (RentPayload memory payload, bytes memory signature) = abi.decode(
738:             zoneParams.extraData,
739:             (RentPayload, bytes)
740:         );
741: 
742:         
743:         SeaportPayload memory seaportPayload = SeaportPayload({
744:             orderHash: zoneParams.orderHash,
745:             zoneHash: zoneParams.zoneHash,
746:             offer: zoneParams.offer,
747:             consideration: zoneParams.consideration,
748:             totalExecutions: zoneParams.totalExecutions,
749:             fulfiller: zoneParams.fulfiller,
750:             offerer: zoneParams.offerer
751:         });
752: 
753:         
754:         _validateProtocolSignatureExpiration(payload.expiration);
755: 
756:         
757:         _validateFulfiller(payload.intendedFulfiller, seaportPayload.fulfiller);
758: 
759:         
760:         address signer = _recoverSignerFromPayload(
761:             _deriveRentPayloadHash(payload),
762:             signature
763:         );
764: 
765:         
766:         if (!kernel.hasRole(signer, toRole("CREATE_SIGNER"))) {
767:             revert Errors.CreatePolicy_UnauthorizedCreatePolicySigner();
768:         }
769: 
770:         
771:         _rentFromZone(payload, seaportPayload);
772: 
773:         
774:         validOrderMagicValue = ZoneInterface.validateOrder.selector;
775:     }

```


*GitHub* : [733](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L733-L733)
### [G-57]<a name="g-57"></a> Cache address(this) when used more than once

*There are 2 instance(s) of this issue:*

```solidity
71:     function reclaimRentalOrder(RentalOrder calldata rentalOrder) external {
72:         
73:         if (address(this) == original) { // <= FOUND
74:             revert Errors.ReclaimerPackage_OnlyDelegateCallAllowed();
75:         }
76: 
77:         
78:         
79:         
80:         if (address(this) != rentalOrder.rentalWallet) { // <= FOUND
81:             revert Errors.ReclaimerPackage_OnlyRentalSafeAllowed(
82:                 rentalOrder.rentalWallet
83:             );
84:         }
85: 
86:         
87:         uint256 itemCount = rentalOrder.items.length;
88: 
89:         
90:         for (uint256 i = 0; i < itemCount; ++i) {
91:             Item memory item = rentalOrder.items[i];
92: 
93:             
94:             if (item.itemType == ItemType.ERC721)
95:                 _transferERC721(item, rentalOrder.lender);
96: 
97:             
98:             if (item.itemType == ItemType.ERC1155)
99:                 _transferERC1155(item, rentalOrder.lender);
100:         }
101:     }

```


*GitHub* : [71](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L71-L80)

```solidity
122:     function initializeRentalSafe(address _stopPolicy, address _guardPolicy) external {
123:         
124:         ISafe(address(this)).enableModule(_stopPolicy); // <= FOUND
125: 
126:         
127:         ISafe(address(this)).setGuard(_guardPolicy); // <= FOUND
128:     }

```


*GitHub* : [122](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L122-L127)
### [G-58]<a name="g-58"></a> bytes.concat() can be used in place of abi.encodePacked
Given concatenation is not going to be used for hashing bytes.concat is the preferred method to use as its more gas efficient when used with bytes variables

*There are 7 instance(s) of this issue:*

```solidity
352:         
353:         bytes memory itemTypeString = abi.encodePacked( // <= FOUND
354:             "Item(uint8 itemType,uint8 settleTo,address token,uint256 amount,uint256 identifier)"
355:         );

```


*GitHub* : [352](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L352-L353)

```solidity
357: 
358:         
359:         bytes memory hookTypeString = abi.encodePacked( // <= FOUND
360:             "Hook(address target,uint256 itemIndex,bytes extraData)" // <= FOUND
361:         );

```


*GitHub* : [357](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L357-L360)

```solidity
362: 
363:         
364:         bytes memory rentalOrderTypeString = abi.encodePacked( // <= FOUND
365:             "RentalOrder(bytes32 seaportOrderHash,Item[] items,Hook[] hooks,uint8 orderType,address lender,address renter,address rentalWallet,uint256 startTimestamp,uint256 endTimestamp)" // <= FOUND
366:         );

```


*GitHub* : [362](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L362-L365)

```solidity
379:             
380:             bytes memory orderFulfillmentTypeString = abi.encodePacked( // <= FOUND
381:                 "OrderFulfillment(address recipient)"
382:             );

```


*GitHub* : [379](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L379-L380)

```solidity
384: 
385:             
386:             bytes memory orderMetadataTypeString = abi.encodePacked( // <= FOUND
387:                 "OrderMetadata(uint8 orderType,uint256 rentDuration,Hook[] hooks,bytes emittedExtraData)" // <= FOUND
388:             );

```


*GitHub* : [384](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L384-L387)

```solidity
389: 
390:             
391:             bytes memory rentPayloadTypeString = abi.encodePacked( // <= FOUND
392:                 "RentPayload(OrderFulfillment fulfillment,OrderMetadata metadata,uint256 expiration,address intendedFulfiller)"
393:             );

```


*GitHub* : [389](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L389-L391)

```solidity
89:         
90:         bytes32 addressHash = keccak256( // <= FOUND
91:             abi.encodePacked(create2_ff, address(this), salt, keccak256(initCode)) // <= FOUND
92:         );

```


*GitHub* : [89](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L89-L91)
### [G-59]<a name="g-59"></a> Empty functions should be removed to save gas

*There are 5 instance(s) of this issue:*

```solidity
353:     function checkAfterExecution(bytes32 txHash, bool success) external override {}

```


*GitHub* : [353](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L353-L353)

```solidity
100:     function VERSION() external pure virtual returns (uint8 major, uint8 minor) {}

```


*GitHub* : [100](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L100-L100)

```solidity
106:     function INIT() external virtual onlyKernel {}

```


*GitHub* : [106](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L106-L106)

```solidity
148:     function configureDependencies()
149:         external
150:         virtual
151:         onlyKernel
152:         returns (Keycode[] memory dependencies)
153:     {}

```


*GitHub* : [148](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L148-L148)

```solidity
166:     function requestPermissions()
167:         external
168:         view
169:         virtual
170:         onlyKernel
171:         returns (Permissions[] memory requests)
172:     {}

```


*GitHub* : [166](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L166-L166)### NonCritical Risk Issues


### [N-01]<a name="n-01"></a> Assembly block creates dirty bits 
Manipulating data directly at the free memory pointer location without subsequently adjusting the pointer can lead to unwanted data remnants, or "dirty bits", in that memory spot. This can cause challenges for the Solidity optimizer, making it difficult to determine if memory cleaning is required before reuse, potentially resulting in less efficient optimization. To mitigate this issue, it's advised to always update the free memory pointer following any data write operation. Furthermore, using the `assembly ("memory-safe") { ... }` annotation will clearly indicate to the optimizer the sections of your code that are memory-safe, improving code efficiency and reducing the potential for errors.

*There are 1 instance(s) of this issue:*

```solidity
40:         assembly {
41:             
42:             if eq(mload(rentalAssets), 0) {
43:                 
44:                 mstore(rentalAssets, 0x20)
45: 
46:                 
47:                 mstore(add(0x20, rentalAssets), 0x00)
48:             }
49: 
50:             
51:             
52:             let newByteDataSize := add(mload(rentalAssets), 0x40) // <= FOUND
53: 
54:             
55:             let rentalAssetElementPtr := add(rentalAssets, 0x20)
56: 
57:             
58:             let elements := add(mload(rentalAssetElementPtr), 1)
59: 
60:             
61:             
62:             
63:             
64:             let newItemPosition := add(
65:                 rentalAssetElementPtr,
66:                 sub(mul(elements, 0x40), 0x20) // <= FOUND
67:             )
68: 
69:             
70:             mstore(rentalAssets, newByteDataSize)
71: 
72:             
73:             mstore(rentalAssetElementPtr, elements)
74: 
75:             
76:             mstore(newItemPosition, _rentalId)
77: 
78:             
79:             mstore(add(newItemPosition, 0x20), rentalAssetAmount)
80: 
81:             
82:             
83:             mstore(0x40, add(newItemPosition, 0x40)) // <= FOUND
84:         }

```


*GitHub* : [52](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L52-L83)
### [N-02]<a name="n-02"></a> Cyclomatic complexity in functions 
Cyclomatic complexity is a software metric used to measure the complexity of a program. It quantifies the number of linearly independent paths through a program's source code, giving an idea of how complex the control flow is. High cyclomatic complexity may indicate a higher risk of defects and can make the code harder to understand, test, and maintain. It often suggests that a function or method is trying to do too much, and a refactor might be needed. By breaking down complex functions into smaller, more focused pieces, you can improve readability, ease of testing, and overall maintainability.

*There are 2 instance(s) of this issue:*

```solidity
195:     function _checkTransaction(address from, address to, bytes memory data) private view { // <= FOUND
196:         bytes4 selector;
197: 
198:         
199:         assembly {
200:             selector := mload(add(data, 0x20))
201:         }
202: 
203:         if (selector == e721_safe_transfer_from_1_selector) {
204:             
205:             uint256 tokenId = uint256(
206:                 _loadValueFromCalldata(data, e721_safe_transfer_from_1_token_id_offset)
207:             );
208: 
209:             
210:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
211:         } else if (selector == e721_safe_transfer_from_2_selector) {
212:             
213:             uint256 tokenId = uint256(
214:                 _loadValueFromCalldata(data, e721_safe_transfer_from_2_token_id_offset)
215:             );
216: 
217:             
218:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
219:         } else if (selector == e721_transfer_from_selector) {
220:             
221:             uint256 tokenId = uint256(
222:                 _loadValueFromCalldata(data, e721_transfer_from_token_id_offset)
223:             );
224: 
225:             
226:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
227:         } else if (selector == e721_approve_selector) {
228:             
229:             uint256 tokenId = uint256(
230:                 _loadValueFromCalldata(data, e721_approve_token_id_offset)
231:             );
232: 
233:             
234:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
235:         } else if (selector == e1155_safe_transfer_from_selector) {
236:             
237:             uint256 tokenId = uint256(
238:                 _loadValueFromCalldata(data, e1155_safe_transfer_from_token_id_offset)
239:             );
240: 
241:             
242:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
243:         } else if (selector == gnosis_safe_enable_module_selector) {
244:             

```


*GitHub* : [195](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L195-L195)

```solidity
277:     function executeAction(Actions action_, address target_) external onlyExecutor { // <= FOUND
278:         if (action_ == Actions.InstallModule) {
279:             ensureContract(target_);
280:             ensureValidKeycode(Module(target_).KEYCODE());
281:             _installModule(Module(target_));
282:         } else if (action_ == Actions.UpgradeModule) {
283:             ensureContract(target_);
284:             ensureValidKeycode(Module(target_).KEYCODE());
285:             _upgradeModule(Module(target_));
286:         } else if (action_ == Actions.ActivatePolicy) {
287:             ensureContract(target_);
288:             _activatePolicy(Policy(target_));
289:         } else if (action_ == Actions.DeactivatePolicy) {
290:             ensureContract(target_);
291:             _deactivatePolicy(Policy(target_));
292:         } else if (action_ == Actions.MigrateKernel) {
293:             ensureContract(target_);
294:             _migrateKernel(Kernel(target_));
295:         } else if (action_ == Actions.ChangeExecutor) {
296:             executor = target_;
297:         } else if (action_ == Actions.ChangeAdmin) {
298:             admin = target_;
299:         }
300: 
301:         emit Events.ActionExecuted(action_, target_);
302:     }

```


*GitHub* : [277](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L277-L277)
### [N-03]<a name="n-03"></a> Code does not follow the best practice of check-effects-interaction 
The "check-effects-interaction" pattern is a best practice in smart contract development, emphasizing the order of operations in functions to prevent reentrancy attacks. Violations arise when a function interacts with external contracts before settling internal state changes or checks. This misordering can expose the contract to potential threats. To adhere to this pattern, first ensure all conditions or checks are satisfied, then update any internal states, and only after these steps, interact with external contracts or addresses. Rearranging operations to this recommended sequence bolsters contract security and aligns with established best practices in the Ethereum community.

*There are 1 instance(s) of this issue:*

```solidity
277:     function executeAction(Actions action_, address target_) external onlyExecutor { // <= FOUND
278:         if (action_ == Actions.InstallModule) {
279:             ensureContract(target_);
280:             ensureValidKeycode(Module(target_).KEYCODE()); // <= FOUND
281:             _installModule(Module(target_));
282:         } else if (action_ == Actions.UpgradeModule) {
283:             ensureContract(target_);
284:             ensureValidKeycode(Module(target_).KEYCODE()); // <= FOUND
285:             _upgradeModule(Module(target_));
286:         } else if (action_ == Actions.ActivatePolicy) {
287:             ensureContract(target_);
288:             _activatePolicy(Policy(target_));
289:         } else if (action_ == Actions.DeactivatePolicy) {
290:             ensureContract(target_);
291:             _deactivatePolicy(Policy(target_));
292:         } else if (action_ == Actions.MigrateKernel) {
293:             ensureContract(target_);
294:             _migrateKernel(Kernel(target_));
295:         } else if (action_ == Actions.ChangeExecutor) {
296:             executor = target_;
297:         } else if (action_ == Actions.ChangeAdmin) {
298:             admin = target_;
299:         }
300: 
301:         emit Events.ActionExecuted(action_, target_);
302:     }

```


*GitHub* : [277](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L277-L284)
### [N-04]<a name="n-04"></a> Events may be emitted out of order due to code not follow the best practice of check-effects-interaction 
The "check-effects-interaction" pattern also impacts event ordering. When a contract doesn't adhere to this pattern, events might be emitted in a sequence that doesn't reflect the actual logical flow of operations. This can cause confusion during event tracking, potentially leading to erroneous off-chain interpretations. To rectify this, always ensure that checks are performed first, state modifications come next, and interactions with external contracts or addresses are done last. This will ensure events are emitted in a logical, consistent manner, providing a clear and accurate chronological record of on-chain actions for off-chain systems and observers.

*There are 1 instance(s) of this issue:*

```solidity
277:     function executeAction(Actions action_, address target_) external onlyExecutor { // <= FOUND
278:         if (action_ == Actions.InstallModule) {
279:             ensureContract(target_);
280:             ensureValidKeycode(Module(target_).KEYCODE()); // <= FOUND
281:             _installModule(Module(target_));
282:         } else if (action_ == Actions.UpgradeModule) {
283:             ensureContract(target_);
284:             ensureValidKeycode(Module(target_).KEYCODE()); // <= FOUND
285:             _upgradeModule(Module(target_));
286:         } else if (action_ == Actions.ActivatePolicy) {
287:             ensureContract(target_);
288:             _activatePolicy(Policy(target_));
289:         } else if (action_ == Actions.DeactivatePolicy) {
290:             ensureContract(target_);
291:             _deactivatePolicy(Policy(target_));
292:         } else if (action_ == Actions.MigrateKernel) {
293:             ensureContract(target_);
294:             _migrateKernel(Kernel(target_));
295:         } else if (action_ == Actions.ChangeExecutor) {
296:             executor = target_;
297:         } else if (action_ == Actions.ChangeAdmin) {
298:             admin = target_;
299:         }
300: 
301:         emit Events.ActionExecuted(action_, target_); // <= FOUND
302:     }

```


*GitHub* : [277](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L277-L301)
### [N-05]<a name="n-05"></a> For extended 'using-for' usage, use the latest pragma version 
Solidity versions of 0.8.13 or above can make use of enhanced using-for notation within contracts.

*There are 4 instance(s) of this issue:*

```solidity
37: contract PaymentEscrow is Proxiable, Module, PaymentEscrowBase 

```


*GitHub* :

```solidity
66: contract Storage is Proxiable, Module, StorageBase 

```


*GitHub* :

```solidity
41: contract Create is Policy, Signer, Zone, Accumulator 

```


*GitHub* :

```solidity
34: contract Stop is Policy, Signer, Reclaimer, Accumulator 

```


*GitHub* :
### [N-06]<a name="n-06"></a> .call bypasses function existence check, type checking and argument packing 
Using the `.call` method in Solidity enables direct communication with an address, bypassing function existence checks, type checking, and argument packing. While this can save gas and provide flexibility, it can also introduce security risks and potential errors. The absence of these checks can lead to unexpected behavior if the callee contract's interface changes or if the input parameters are not crafted with care. The resolution to these issues is to use Solidity's high-level interface for calling functions when possible, as it automatically manages these aspects. If using `.call` is necessary, ensure that the inputs are carefully validated and that awareness of the called contract's behavior is maintained.

*There are 1 instance(s) of this issue:*

```solidity
102:         
103:         (bool success, bytes memory data) = token.call( // <= FOUND
104:             abi.encodeWithSelector(IERC20.transfer.selector, to, value)
105:         );

```


*GitHub* : [102](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L102-L103)
### [N-07]<a name="n-07"></a> Double type casts create complexity within the code 
Double type casting should be avoided in Solidity contracts to prevent unintended consequences and ensure accurate data representation. Performing multiple type casts in succession can lead to unexpected truncation, rounding errors, or loss of precision, potentially compromising the contract's functionality and reliability. Furthermore, double type casting can make the code less readable and harder to maintain, increasing the likelihood of errors and misunderstandings during development and debugging. To ensure precise and consistent data handling, developers should use appropriate data types and avoid unnecessary or excessive type casting, promoting a more robust and dependable contract execution.

*There are 1 instance(s) of this issue:*

```solidity
94: 
95:         
96:         return address(uint160(uint256(addressHash))); // <= FOUND

```


*GitHub* : [96](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L96-L96)
### [N-08]<a name="n-08"></a> Inconsistent comment spacing 
Some comments use // X and others //X Amend comments to use only use // X or //X consistently

*There are 1 instance(s) of this issue:*

```solidity
102: //github.com/martinetlee/create2-snippets#method-1-mixing-with-salt

```


*GitHub* : [102](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L102-L102)
### [N-09]<a name="n-09"></a> Consider adding emergency-stop functionality 
In the event of a security breach or any unforeseen emergency, swiftly suspending all protocol operations becomes crucial. Having a mechanism in place to halt all functions collectively, instead of pausing individual contracts separately, substantially enhances the efficiency of mitigating ongoing attacks or vulnerabilities. This not only quickens the response time to potential threats but also reduces operational stress during these critical periods. Therefore, consider integrating a 'circuit breaker' or 'emergency stop' function into the smart contract system architecture. Such a feature would provide the capability to suspend the entire protocol instantly, which could prove invaluable during a time-sensitive crisis management situation.

*There are 11 instance(s) of this issue:*

```solidity
23: contract PaymentEscrowBase 

```


*GitHub* : [23](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L23-L23)

```solidity
37: contract PaymentEscrow is Proxiable, Module, PaymentEscrowBase 

```


*GitHub* : [37](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L37-L37)

```solidity
14: contract StorageBase 

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L14-L14)

```solidity
66: contract Storage is Proxiable, Module, StorageBase 

```


*GitHub* : [66](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L66-L66)

```solidity
15: contract Admin is Policy 

```


*GitHub* : [15](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L15-L15)

```solidity
41: contract Create is Policy, Signer, Zone, Accumulator 

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L41-L41)

```solidity
22: contract Factory is Policy 

```


*GitHub* : [22](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L22-L22)

```solidity
39: contract Guard is Policy, BaseGuard 

```


*GitHub* : [39](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L39-L39)

```solidity
34: contract Stop is Policy, Signer, Reclaimer, Accumulator 

```


*GitHub* : [34](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L34-L34)

```solidity
14: contract Create2Deployer 

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L14-L14)

```solidity
206: contract Kernel 

```


*GitHub* : [206](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L206-L206)
### [N-10]<a name="n-10"></a> Employ Explicit Casting to Bytes or Bytes32 for Enhanced Code Clarity and Meaning 
Smart contracts are complex entities, and clarity in their operations is fundamental to ensure that they function as intended. Casting a single argument instead of utilizing 'abi.encodePacked()' improves the transparency of the operation. It elucidates the intent of the code, reducing ambiguity and making it easier for auditors and developers to understand the code’s purpose. Such practices promote readability and maintainability, thus reducing the likelihood of errors and misunderstandings. Therefore, it's recommended to employ explicit casts for single arguments where possible, to increase the contract's comprehensibility and ensure a smoother review process.

*There are 4 instance(s) of this issue:*

```solidity
162:     function _deriveRentalOrderHash(
163:         RentalOrder memory order
164:     ) internal view returns (bytes32) {
165:         
166:         bytes32[] memory itemHashes = new bytes32[](order.items.length);
167:         bytes32[] memory hookHashes = new bytes32[](order.hooks.length);
168: 
169:         
170:         for (uint256 i = 0; i < order.items.length; ++i) {
171:             
172:             itemHashes[i] = _deriveItemHash(order.items[i]);
173:         }
174: 
175:         
176:         for (uint256 i = 0; i < order.hooks.length; ++i) {
177:             
178:             hookHashes[i] = _deriveHookHash(order.hooks[i]);
179:         }
180: 
181:         return
182:             keccak256(
183:                 abi.encode(
184:                     _RENTAL_ORDER_TYPEHASH,
185:                     order.seaportOrderHash,
186:                     keccak256(abi.encodePacked(itemHashes)), // <= FOUND
187:                     keccak256(abi.encodePacked(hookHashes)), // <= FOUND
188:                     order.orderType,
189:                     order.lender,
190:                     order.renter,
191:                     order.startTimestamp,
192:                     order.endTimestamp
193:                 )
194:             );
195:     }

```


*GitHub* : [186](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L186-L187)

```solidity
218:     function _deriveOrderMetadataHash(
219:         OrderMetadata memory metadata
220:     ) internal view returns (bytes32) {
221:         
222:         bytes32[] memory hookHashes = new bytes32[](metadata.hooks.length);
223: 
224:         
225:         for (uint256 i = 0; i < metadata.hooks.length; ++i) {
226:             
227:             hookHashes[i] = _deriveHookHash(metadata.hooks[i]);
228:         }
229: 
230:         
231:         return
232:             keccak256(
233:                 abi.encode(
234:                     _ORDER_METADATA_TYPEHASH,
235:                     metadata.rentDuration,
236:                     keccak256(abi.encodePacked(hookHashes)) // <= FOUND
237:                 )
238:             );
239:     }

```


*GitHub* : [236](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L236-L236)

```solidity
339:     function _deriveRentalTypehashes()
340:         internal
341:         pure
342:         returns (
343:             bytes32 itemTypeHash,
344:             bytes32 hookTypeHash,
345:             bytes32 rentalOrderTypeHash,
346:             bytes32 orderFulfillmentTypeHash,
347:             bytes32 orderMetadataTypeHash,
348:             bytes32 rentPayloadTypeHash
349:         )
350:     {
351:         
352:         bytes memory itemTypeString = abi.encodePacked( // <= FOUND
353:             "Item(uint8 itemType,uint8 settleTo,address token,uint256 amount,uint256 identifier)"
354:         );
355: 
356:         
357:         bytes memory hookTypeString = abi.encodePacked( // <= FOUND
358:             "Hook(address target,uint256 itemIndex,bytes extraData)"
359:         );
360: 
361:         
362:         bytes memory rentalOrderTypeString = abi.encodePacked( // <= FOUND
363:             "RentalOrder(bytes32 seaportOrderHash,Item[] items,Hook[] hooks,uint8 orderType,address lender,address renter,address rentalWallet,uint256 startTimestamp,uint256 endTimestamp)"
364:         );
365: 
366:         
367:         itemTypeHash = keccak256(itemTypeString);
368: 
369:         
370:         hookTypeHash = keccak256(hookTypeString);
371: 
372:         
373:         rentalOrderTypeHash = keccak256(
374:             abi.encode(rentalOrderTypeString, hookTypeString, itemTypeString)
375:         );
376: 
377:         {
378:             
379:             bytes memory orderFulfillmentTypeString = abi.encodePacked( // <= FOUND
380:                 "OrderFulfillment(address recipient)"
381:             );
382: 
383:             
384:             bytes memory orderMetadataTypeString = abi.encodePacked( // <= FOUND
385:                 "OrderMetadata(uint8 orderType,uint256 rentDuration,Hook[] hooks,bytes emittedExtraData)"
386:             );
387: 
388:             
389:             bytes memory rentPayloadTypeString = abi.encodePacked( // <= FOUND
390:                 "RentPayload(OrderFulfillment fulfillment,OrderMetadata metadata,uint256 expiration,address intendedFulfiller)"
391:             );
392: 
393:             
394:             rentPayloadTypeHash = keccak256(
395:                 abi.encodePacked( // <= FOUND
396:                     rentPayloadTypeString,
397:                     orderMetadataTypeString,
398:                     orderFulfillmentTypeString
399:                 )
400:             );
401: 
402:             
403:             orderFulfillmentTypeHash = keccak256(orderFulfillmentTypeString);
404: 
405:             
406:             orderMetadataTypeHash = keccak256(orderMetadataTypeString);
407:         }
408:     }

```


*GitHub* : [352](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L352-L395)

```solidity
84:     function getCreate2Address(
85:         bytes32 salt,
86:         bytes memory initCode
87:     ) public view returns (address) {
88:         
89:         bytes32 addressHash = keccak256(
90:             abi.encodePacked(create2_ff, address(this), salt, keccak256(initCode)) // <= FOUND
91:         );
92: 
93:         
94:         return address(uint160(uint256(addressHash)));
95:     }

```


*GitHub* : [90](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L90-L90)
### [N-11]<a name="n-11"></a> Missing events in sensitive functions 
Sensitive setter functions in smart contracts often alter critical state variables. Without events emitted in these functions, external observers or dApps cannot easily track or react to these state changes. Missing events can obscure contract activity, hampering transparency and making integration more challenging. To resolve this, incorporate appropriate event emissions within these functions. Events offer an efficient way to log crucial changes, aiding in real-time tracking and post-transaction verification.

*There are 7 instance(s) of this issue:*

```solidity
380:     function setFee(uint256 feeNumerator) external onlyByProxy permissioned { // <= FOUND
381:         
382:         if (feeNumerator > 10000) {
383:             revert Errors.PaymentEscrow_InvalidFeeNumerator();
384:         }
385: 
386:         
387:         fee = feeNumerator;
388:     }

```


*GitHub* : [380](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L380-L380)

```solidity
173:     function setFee(uint256 feeNumerator) external onlyRole("ADMIN_ADMIN") { // <= FOUND
174:         ESCRW.setFee(feeNumerator);
175:     }

```


*GitHub* : [173](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L173-L173)

```solidity
192:     function setActiveStatus(bool activate_) external onlyKernel { // <= FOUND
193:         isActive = activate_;
194:     }

```


*GitHub* : [192](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L192-L192)

```solidity
294:     function updateHookPath(address to, address hook) external onlyByProxy permissioned { // <= FOUND
295:         
296:         if (to.code.length == 0) revert Errors.StorageModule_NotContract(to);
297: 
298:         
299:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook);
300: 
301:         
302:         _contractToHook[to] = hook;
303:     }

```


*GitHub* : [294](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L294-L294)

```solidity
313:     function updateHookStatus( // <= FOUND
314:         address hook,
315:         uint8 bitmap
316:     ) external onlyByProxy permissioned {
317:         
318:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook);
319: 
320:         
321:         if (bitmap > uint8(7))
322:             revert Errors.StorageModule_InvalidHookStatusBitmap(bitmap);
323: 
324:         
325:         hookStatus[hook] = bitmap;
326:     }

```


*GitHub* : [313](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L313-L313)

```solidity
362:     function updateHookPath(address to, address hook) external onlyRole("GUARD_ADMIN") { // <= FOUND
363:         STORE.updateHookPath(to, hook);
364:     }

```


*GitHub* : [362](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L362-L362)

```solidity
373:     function updateHookStatus( // <= FOUND
374:         address hook,
375:         uint8 bitmap
376:     ) external onlyRole("GUARD_ADMIN") {
377:         STORE.updateHookStatus(hook, bitmap);
378:     }

```


*GitHub* : [373](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L373-L373)
### [N-12]<a name="n-12"></a> The call abi.encodeWithSelector is not type safe
In Solidity, `abi.encodeWithSelector` is a function used for encoding data along with a function selector, but it is not type-safe. This means it does not enforce type checking at compile time, potentially leading to errors if arguments do not match the expected types. Starting from version 0.8.13, Solidity introduced `abi.encodeCall`, which offers a safer alternative. `abi.encodeCall` ensures type safety by performing a full type check, aligning the types of the arguments with the function signature. This reduces the risk of bugs caused by typographical errors or mismatched types. Using `abi.encodeCall` enhances the reliability and security of the code by ensuring that the encoded data strictly conforms to the specified types, making it a preferable choice in Solidity versions 0.8.13 and above.

*There are 2 instance(s) of this issue:*

```solidity
100:     function _safeTransfer(address token, address to, uint256 value) internal {
101:         
102:         (bool success, bytes memory data) = token.call(
103:             abi.encodeWithSelector(IERC20.transfer.selector, to, value) // <= FOUND
104:         );
105: 
106:         
107:         
108:         
109:         
110:         
111:         
112:         
113:         
114:         
115:         if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
116:             revert Errors.PaymentEscrowModule_PaymentTransferFailed(token, to, value);
117:         }
118:     }

```


*GitHub* : [103](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L103-L103)

```solidity
166:     function _reclaimRentedItems(RentalOrder memory order) internal {
167:         
168:         bool success = ISafe(order.rentalWallet).execTransactionFromModule(
169:             
170:             address(this),
171:             
172:             0,
173:             
174:             abi.encodeWithSelector(this.reclaimRentalOrder.selector, order), // <= FOUND
175:             
176:             Enum.Operation.DelegateCall
177:         );
178: 
179:         
180:         if (!success) {
181:             revert Errors.StopPolicy_ReclaimFailed();
182:         }
183:     }

```


*GitHub* : [174](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L174-L174)
### [N-13]<a name="n-13"></a> Floating pragma should be avoided

*There are 1 instance(s) of this issue:*

```solidity
2: pragma solidity ^0.8.20; // <= FOUND

```


*GitHub* : [2](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L2-L2)
### [N-14]<a name="n-14"></a> Empty function blocks
Empty code blocks (i.e., {}) in a Solidity contract can be harmful as they can lead to ambiguity, misinterpretation, and unintended behavior. When developers encounter empty code blocks, it may be unclear whether the absence of code is intentional or the result of an oversight. This uncertainty can cause confusion during development, testing, and debugging, increasing the likelihood of introducing errors or vulnerabilities. Moreover, empty code blocks may give a false impression of implemented functionality or security measures, creating a misleading sense of assurance. To ensure clarity and maintainability, it is essential to avoid empty code blocks and explicitly document the intended behavior or any intentional omissions.

*There are 5 instance(s) of this issue:*

```solidity
353:     function checkAfterExecution(bytes32 txHash, bool success) external override {}

```


*GitHub* : [353](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L353-L353)

```solidity
100:     function VERSION() external pure virtual returns (uint8 major, uint8 minor) {}

```


*GitHub* : [100](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L100-L100)

```solidity
106:     function INIT() external virtual onlyKernel {}

```


*GitHub* : [106](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L106-L106)

```solidity
148:     function configureDependencies()
149:         external
150:         virtual
151:         onlyKernel
152:         returns (Keycode[] memory dependencies)
153:     {}

```


*GitHub* : [148](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L148-L148)

```solidity
166:     function requestPermissions()
167:         external
168:         view
169:         virtual
170:         onlyKernel
171:         returns (Permissions[] memory requests)
172:     {}

```


*GitHub* : [166](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L166-L166)
### [N-15]<a name="n-15"></a> In functions which accept an address as a parameter, there should be a zero address check to prevent bugs
In smart contract development, especially with Solidity, it's crucial to validate inputs to functions. When a function accepts an Ethereum address as a parameter, implementing a zero address check (i.e., ensuring the address is not `0x0`) is a best practice to prevent potential bugs and vulnerabilities. The zero address (`0x0`) is a default value and generally indicates an uninitialized or invalid state. Passing the zero address to certain functions can lead to unintended behaviors, like funds getting locked permanently or transactions failing silently. By checking for and rejecting the zero address, developers can ensure that the function operates as intended and interacts only with valid Ethereum addresses. This check enhances the contract's robustness and security.

*There are 46 instance(s) of this issue:*

```solidity
100:     function _safeTransfer(address token, address to, uint256 value) internal 

```


*GitHub* : [100](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L100-L100)

```solidity
159:     function _settlePaymentProRata(
160:         address token,
161:         uint256 amount,
162:         address lender,
163:         address renter,
164:         uint256 elapsedTime,
165:         uint256 totalTime
166:     ) internal 

```


*GitHub* : [159](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L159-L159)

```solidity
190:     function _settlePaymentInFull(
191:         address token,
192:         uint256 amount,
193:         SettleTo settleTo,
194:         address lender,
195:         address renter
196:     ) internal 

```


*GitHub* : [190](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L190-L190)

```solidity
215:     function _settlePayment(
216:         Item[] calldata items,
217:         OrderType orderType,
218:         address lender,
219:         address renter,
220:         uint256 start,
221:         uint256 end
222:     ) internal 

```


*GitHub* : [215](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L215-L215)

```solidity
292:     function _decreaseDeposit(address token, uint256 amount) internal 

```


*GitHub* : [292](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L292-L292)

```solidity
304:     function _increaseDeposit(address token, uint256 amount) internal 

```


*GitHub* : [304](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L304-L304)

```solidity
361:     function increaseDeposit(
362:         address token,
363:         uint256 amount
364:     ) external onlyByProxy permissioned 

```


*GitHub* : [361](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L361-L361)

```solidity
397:     function skim(address token, address to) external onlyByProxy permissioned 

```


*GitHub* : [397](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L397-L397)

```solidity
360:     function upgrade(address newImplementation) external onlyByProxy permissioned 

```


*GitHub* : [360](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L360-L360)

```solidity
118:     function isRentedOut(
119:         address recipient,
120:         address token,
121:         uint256 identifier
122:     ) external view returns (bool) 

```


*GitHub* : [118](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L118-L118)

```solidity
135:     function contractToHook(address to) external view returns (address) 

```


*GitHub* : [135](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L135-L135)

```solidity
149:     function hookOnTransaction(address hook) external view returns (bool) 

```


*GitHub* : [149](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L149-L149)

```solidity
159:     function hookOnStart(address hook) external view returns (bool) 

```


*GitHub* : [159](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L159-L159)

```solidity
169:     function hookOnStop(address hook) external view returns (bool) 

```


*GitHub* : [169](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L169-L169)

```solidity
274:     function addRentalSafe(address safe) external onlyByProxy permissioned 

```


*GitHub* : [274](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L274-L274)

```solidity
294:     function updateHookPath(address to, address hook) external onlyByProxy permissioned 

```


*GitHub* : [294](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L294-L294)

```solidity
313:     function updateHookStatus(
314:         address hook,
315:         uint8 bitmap
316:     ) external onlyByProxy permissioned 

```


*GitHub* : [313](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L313-L313)

```solidity
334:     function toggleWhitelistDelegate(
335:         address delegate,
336:         bool isEnabled
337:     ) external onlyByProxy permissioned 

```


*GitHub* : [334](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L334-L334)

```solidity
347:     function toggleWhitelistExtension(
348:         address extension,
349:         bool isEnabled
350:     ) external onlyByProxy permissioned 

```


*GitHub* : [347](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L347-L347)

```solidity
32:     function _transferERC721(Item memory item, address recipient) private 

```


*GitHub* : [32](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L32-L32)

```solidity
42:     function _transferERC1155(Item memory item, address recipient) private 

```


*GitHub* : [42](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L42-L42)

```solidity
76:     function _validateFulfiller(
77:         address intendedFulfiller,
78:         address actualFulfiller
79:     ) internal pure 

```


*GitHub* : [76](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L76-L76)

```solidity
99:     function toggleWhitelistDelegate(
100:         address delegate,
101:         bool isEnabled
102:     ) external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [99](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L99-L99)

```solidity
113:     function toggleWhitelistExtension(
114:         address extension,
115:         bool isEnabled
116:     ) external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [113](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L113-L113)

```solidity
126:     function upgradeStorage(address newImplementation) external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [126](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L126-L126)

```solidity
144:     function upgradePaymentEscrow(
145:         address newImplementation
146:     ) external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [144](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L144-L144)

```solidity
164:     function skim(address token, address to) external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [164](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L164-L164)

```solidity
464:     function _addHooks(
465:         Hook[] memory hooks,
466:         SpentItem[] memory offerItems,
467:         address rentalWallet
468:     ) internal 

```


*GitHub* : [464](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L464-L464)

```solidity
647:     function _isValidSafeOwner(address owner, address safe) internal view 

```


*GitHub* : [647](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L647-L647)

```solidity
666:     function _checkExpectedRecipient(
667:         ReceivedItem memory execution,
668:         address expectedRecipient
669:     ) internal pure 

```


*GitHub* : [666](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L666-L666)

```solidity
691:     function _executionInvariantChecks(
692:         ReceivedItem[] memory executions,
693:         address expectedRentalSafe
694:     ) internal view 

```


*GitHub* : [691](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L691-L691)

```solidity
122:     function initializeRentalSafe(address _stopPolicy, address _guardPolicy) external 

```


*GitHub* : [122](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L122-L122)

```solidity
138:     function deployRentalSafe(
139:         address[] calldata owners,
140:         uint256 threshold
141:     ) external returns (address safe) 

```


*GitHub* : [138](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L138-L138)

```solidity
126:     function _revertSelectorOnActiveRental(
127:         bytes4 selector,
128:         address safe,
129:         address token,
130:         uint256 tokenId
131:     ) private view 

```


*GitHub* : [126](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L126-L126)

```solidity
143:     function _revertNonWhitelistedExtension(address extension) private view 

```


*GitHub* : [143](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L143-L143)

```solidity
159:     function _forwardToHook(
160:         address hook,
161:         address safe,
162:         address to,
163:         uint256 value,
164:         bytes memory data
165:     ) private 

```


*GitHub* : [159](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L159-L159)

```solidity
195:     function _checkTransaction(address from, address to, bytes memory data) private view 

```


*GitHub* : [195](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L195-L195)

```solidity
362:     function updateHookPath(address to, address hook) external onlyRole("GUARD_ADMIN") 

```


*GitHub* : [362](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L362-L362)

```solidity
373:     function updateHookStatus(
374:         address hook,
375:         uint8 bitmap
376:     ) external onlyRole("GUARD_ADMIN") 

```


*GitHub* : [373](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L373-L373)

```solidity
111:     function _emitRentalOrderStopped(bytes32 seaportOrderHash, address stopper) internal 

```


*GitHub* : [111](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L111-L111)

```solidity
126:     function _validateRentalCanBeStoped(
127:         OrderType orderType,
128:         uint256 endTimestamp,
129:         address expectedLender
130:     ) internal view 

```


*GitHub* : [126](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L126-L126)

```solidity
194:     function _removeHooks(
195:         Hook[] calldata hooks,
196:         Item[] calldata rentalItems,
197:         address rentalWallet
198:     ) internal 

```


*GitHub* : [194](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L194-L194)

```solidity
107:     function generateSaltWithSender(
108:         address sender,
109:         bytes12 data
110:     ) public pure returns (bytes32 salt) 

```


*GitHub* : [107](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L107-L107)

```solidity
277:     function executeAction(Actions action_, address target_) external onlyExecutor 

```


*GitHub* : [277](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L277-L277)

```solidity
310:     function grantRole(Role role_, address addr_) public onlyAdmin 

```


*GitHub* : [310](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L310-L310)

```solidity
333:     function revokeRole(Role role_, address addr_) public onlyAdmin 

```


*GitHub* : [333](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L333-L333)
### [N-16]<a name="n-16"></a> Enum values should be used in place of constant array indexes
Create a commented enum value to use in place of constant array indexes, this makes the code far easier to understand

*There are 19 instance(s) of this issue:*

```solidity
81: 
82:         dependencies[0] = toKeycode("STORE"); // <= FOUND

```


*GitHub* : [81](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L81-L82)

```solidity
72:         requests[0] = Permissions( // <= FOUND
73:             toKeycode("STORE"),
74:             STORE.toggleWhitelistExtension.selector
75:         );

```


*GitHub* : [72](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L72-L72)

```solidity
104:         requests[0] = Permissions(toKeycode("STORE"), STORE.addRentals.selector); // <= FOUND

```


*GitHub* : [104](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L104-L104)

```solidity
102:         requests[0] = Permissions(toKeycode("STORE"), STORE.addRentalSafe.selector); // <= FOUND

```


*GitHub* : [102](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L102-L102)

```solidity
92:         requests[0] = Permissions(toKeycode("STORE"), STORE.updateHookPath.selector); // <= FOUND

```


*GitHub* : [92](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L92-L92)

```solidity
95:         requests[0] = Permissions(toKeycode("STORE"), STORE.removeRentals.selector); // <= FOUND

```


*GitHub* : [95](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L95-L95)

```solidity
83: 
84:         dependencies[1] = toKeycode("ESCRW"); // <= FOUND

```


*GitHub* : [83](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L83-L84)

```solidity
76:         requests[1] = Permissions( // <= FOUND
77:             toKeycode("STORE"),
78:             STORE.toggleWhitelistDelegate.selector
79:         );

```


*GitHub* : [76](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L76-L76)

```solidity
105:         requests[1] = Permissions(toKeycode("ESCRW"), ESCRW.increaseDeposit.selector); // <= FOUND

```


*GitHub* : [105](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L105-L105)

```solidity
93:         requests[1] = Permissions(toKeycode("STORE"), STORE.updateHookStatus.selector); // <= FOUND

```


*GitHub* : [93](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L93-L93)

```solidity
96:         requests[1] = Permissions(toKeycode("STORE"), STORE.removeRentalsBatch.selector); // <= FOUND

```


*GitHub* : [96](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L96-L96)

```solidity
80:         requests[2] = Permissions(toKeycode("STORE"), STORE.upgrade.selector); // <= FOUND

```


*GitHub* : [80](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L80-L80)

```solidity
97:         requests[2] = Permissions(toKeycode("ESCRW"), ESCRW.settlePayment.selector); // <= FOUND

```


*GitHub* : [97](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L97-L97)

```solidity
81:         requests[3] = Permissions(toKeycode("STORE"), STORE.freeze.selector); // <= FOUND

```


*GitHub* : [81](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L81-L81)

```solidity
98:         requests[3] = Permissions(toKeycode("ESCRW"), ESCRW.settlePaymentBatch.selector); // <= FOUND

```


*GitHub* : [98](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L98-L98)

```solidity
83: 
84:         requests[4] = Permissions(toKeycode("ESCRW"), ESCRW.skim.selector); // <= FOUND

```


*GitHub* : [83](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L83-L84)

```solidity
84:         requests[5] = Permissions(toKeycode("ESCRW"), ESCRW.setFee.selector); // <= FOUND

```


*GitHub* : [84](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L84-L84)

```solidity
85:         requests[6] = Permissions(toKeycode("ESCRW"), ESCRW.upgrade.selector); // <= FOUND

```


*GitHub* : [85](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L85-L85)

```solidity
86:         requests[7] = Permissions(toKeycode("ESCRW"), ESCRW.freeze.selector); // <= FOUND

```


*GitHub* : [86](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L86-L86)
### [N-17]<a name="n-17"></a> Default int values are manually set
In instances where a new variable is defined, there is no need to set it to it's default value.

*There are 15 instance(s) of this issue:*

```solidity
599: 
600:         
601:         for (uint256 i = 0; i < items.length; ++i) { // <= FOUND

```


*GitHub* : [599](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L599-L601)

```solidity
324:         
325:         for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L324-L325)

```solidity
197: 
198:         
199:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) { // <= FOUND

```


*GitHub* : [197](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L197-L199)

```solidity
249:         
250:         for (uint256 i = 0; i < orderHashes.length; ++i) { // <= FOUND

```


*GitHub* : [249](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L249-L250)

```solidity
120: 
121:         
122:         
123:         for (uint256 i = 0; i < rentalAssetUpdateLength; ++i) { // <= FOUND

```


*GitHub* : [120](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L120-L123)

```solidity
90: 
91:         
92:         for (uint256 i = 0; i < itemCount; ++i) { // <= FOUND

```


*GitHub* : [90](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L90-L92)

```solidity
170: 
171:         
172:         for (uint256 i = 0; i < order.items.length; ++i) { // <= FOUND

```


*GitHub* : [170](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L170-L172)

```solidity
176: 
177:         
178:         for (uint256 i = 0; i < order.hooks.length; ++i) { // <= FOUND

```


*GitHub* : [176](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L176-L178)

```solidity
225: 
226:         
227:         for (uint256 i = 0; i < metadata.hooks.length; ++i) { // <= FOUND

```


*GitHub* : [225](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L225-L227)

```solidity
475: 
476:         
477:         for (uint256 i = 0; i < hooks.length; ++i) { // <= FOUND

```


*GitHub* : [475](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L475-L477)

```solidity
599: 
600:             
601:             
602:             for (uint256 i = 0; i < items.length; ++i) { // <= FOUND

```


*GitHub* : [599](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L599-L602)

```solidity
695:         for (uint256 i = 0; i < executions.length; ++i) { // <= FOUND

```


*GitHub* : [695](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L695-L695)

```solidity
324: 
325:         
326:         
327:         for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L324-L327)

```solidity
333: 
334:             
335:             for (uint256 j = 0; j < orders[i].items.length; ++j) { // <= FOUND

```


*GitHub* : [333](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L333-L335)

```solidity
566:         for (uint256 i = 0; i < reqLength; ++i) { // <= FOUND

```


*GitHub* : [566](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L566-L566)
### [N-18]<a name="n-18"></a> Revert statements within external and public functions can be used to perform DOS attacks
In Solidity, 'revert' statements are used to undo changes and throw an exception when certain conditions are not met. However, in public and external functions, improper use of `revert` can be exploited for Denial of Service (DoS) attacks. An attacker can intentionally trigger these 'revert' conditions, causing legitimate transactions to consistently fail. For example, if a function relies on specific conditions from user input or contract state, an attacker could manipulate these to continually force reverts, blocking the function's execution. Therefore, it's crucial to design contract logic to handle exceptions properly and avoid scenarios where `revert` can be predictably triggered by malicious actors. This includes careful input validation and considering alternative design patterns that are less susceptible to such abuses.

*There are 13 instance(s) of this issue:*

```solidity
361:     function increaseDeposit(
362:         address token,
363:         uint256 amount
364:     ) external onlyByProxy permissioned {
365:         
366:         if (amount == 0) {
367:             revert Errors.PaymentEscrow_ZeroPayment(); // <= FOUND
368:         }
369: 
370:         
371:         _increaseDeposit(token, amount);
372:     }

```


*GitHub* : [367](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L367-L367)

```solidity
380:     function setFee(uint256 feeNumerator) external onlyByProxy permissioned {
381:         
382:         if (feeNumerator > 10000) {
383:             revert Errors.PaymentEscrow_InvalidFeeNumerator(); // <= FOUND
384:         }
385: 
386:         
387:         fee = feeNumerator;
388:     }

```


*GitHub* : [383](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L383-L383)

```solidity
216:     function removeRentals(
217:         bytes32 orderHash,
218:         RentalAssetUpdate[] calldata rentalAssetUpdates
219:     ) external onlyByProxy permissioned {
220:         
221:         if (!orders[orderHash]) {
222:             revert Errors.StorageModule_OrderDoesNotExist(orderHash); // <= FOUND
223:         } else {
224:             
225:             delete orders[orderHash];
226:         }
227: 
228:         
229:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {
230:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
231: 
232:             
233:             rentedAssets[asset.rentalId] -= asset.amount;
234:         }
235:     }

```


*GitHub* : [222](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L222-L222)

```solidity
244:     function removeRentalsBatch(
245:         bytes32[] calldata orderHashes,
246:         RentalAssetUpdate[] calldata rentalAssetUpdates
247:     ) external onlyByProxy permissioned {
248:         
249:         for (uint256 i = 0; i < orderHashes.length; ++i) {
250:             
251:             if (!orders[orderHashes[i]]) {
252:                 revert Errors.StorageModule_OrderDoesNotExist(orderHashes[i]); // <= FOUND
253:             } else {
254:                 
255:                 delete orders[orderHashes[i]];
256:             }
257:         }
258: 
259:         
260:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {
261:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
262: 
263:             
264:             rentedAssets[asset.rentalId] -= asset.amount;
265:         }
266:     }

```


*GitHub* : [252](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L252-L252)

```solidity
294:     function updateHookPath(address to, address hook) external onlyByProxy permissioned {
295:         
296:         if (to.code.length == 0) revert Errors.StorageModule_NotContract(to); // <= FOUND
297: 
298:         
299:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook); // <= FOUND
300: 
301:         
302:         _contractToHook[to] = hook;
303:     }

```


*GitHub* : [296](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L296-L299)

```solidity
313:     function updateHookStatus(
314:         address hook,
315:         uint8 bitmap
316:     ) external onlyByProxy permissioned {
317:         
318:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook); // <= FOUND
319: 
320:         
321:         if (bitmap > uint8(7))
322:             revert Errors.StorageModule_InvalidHookStatusBitmap(bitmap); // <= FOUND
323: 
324:         
325:         hookStatus[hook] = bitmap;
326:     }

```


*GitHub* : [318](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L318-L322)

```solidity
71:     function reclaimRentalOrder(RentalOrder calldata rentalOrder) external {
72:         
73:         if (address(this) == original) {
74:             revert Errors.ReclaimerPackage_OnlyDelegateCallAllowed(); // <= FOUND
75:         }
76: 
77:         
78:         
79:         
80:         if (address(this) != rentalOrder.rentalWallet) {
81:             revert Errors.ReclaimerPackage_OnlyRentalSafeAllowed( // <= FOUND
82:                 rentalOrder.rentalWallet
83:             );
84:         }
85: 
86:         
87:         uint256 itemCount = rentalOrder.items.length;
88: 
89:         
90:         for (uint256 i = 0; i < itemCount; ++i) {
91:             Item memory item = rentalOrder.items[i];
92: 
93:             
94:             if (item.itemType == ItemType.ERC721)
95:                 _transferERC721(item, rentalOrder.lender);
96: 
97:             
98:             if (item.itemType == ItemType.ERC1155)
99:                 _transferERC1155(item, rentalOrder.lender);
100:         }
101:     }

```


*GitHub* : [74](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L74-L81)

```solidity
733:     function validateOrder(
734:         ZoneParameters calldata zoneParams
735:     ) external override onlyRole("SEAPORT") returns (bytes4 validOrderMagicValue) {
736:         
737:         (RentPayload memory payload, bytes memory signature) = abi.decode(
738:             zoneParams.extraData,
739:             (RentPayload, bytes)
740:         );
741: 
742:         
743:         SeaportPayload memory seaportPayload = SeaportPayload({
744:             orderHash: zoneParams.orderHash,
745:             zoneHash: zoneParams.zoneHash,
746:             offer: zoneParams.offer,
747:             consideration: zoneParams.consideration,
748:             totalExecutions: zoneParams.totalExecutions,
749:             fulfiller: zoneParams.fulfiller,
750:             offerer: zoneParams.offerer
751:         });
752: 
753:         
754:         _validateProtocolSignatureExpiration(payload.expiration);
755: 
756:         
757:         _validateFulfiller(payload.intendedFulfiller, seaportPayload.fulfiller);
758: 
759:         
760:         address signer = _recoverSignerFromPayload(
761:             _deriveRentPayloadHash(payload),
762:             signature
763:         );
764: 
765:         
766:         if (!kernel.hasRole(signer, toRole("CREATE_SIGNER"))) {
767:             revert Errors.CreatePolicy_UnauthorizedCreatePolicySigner(); // <= FOUND
768:         }
769: 
770:         
771:         _rentFromZone(payload, seaportPayload);
772: 
773:         
774:         validOrderMagicValue = ZoneInterface.validateOrder.selector;
775:     }

```


*GitHub* : [767](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L767-L767)

```solidity
138:     function deployRentalSafe(
139:         address[] calldata owners,
140:         uint256 threshold
141:     ) external returns (address safe) {
142:         
143:         if (threshold == 0 || threshold > owners.length) {
144:             revert Errors.FactoryPolicy_InvalidSafeThreshold(threshold, owners.length); // <= FOUND
145:         }
146: 
147:         
148:         
149:         bytes memory data = abi.encodeCall(
150:             Factory.initializeRentalSafe,
151:             (address(stopPolicy), address(guardPolicy))
152:         );
153: 
154:         
155:         bytes memory initializerPayload = abi.encodeCall(
156:             ISafe.setup,
157:             (
158:                 
159:                 owners,
160:                 
161:                 threshold,
162:                 
163:                 address(this),
164:                 
165:                 data,
166:                 
167:                 address(fallbackHandler),
168:                 
169:                 address(0),
170:                 
171:                 0,
172:                 
173:                 payable(address(0))
174:             )
175:         );
176: 
177:         
178:         
179:         
180:         safe = address(
181:             safeProxyFactory.createProxyWithNonce(
182:                 address(safeSingleton),
183:                 initializerPayload,
184:                 uint256(keccak256(abi.encode(STORE.totalSafes() + 1, block.chainid)))
185:             )
186:         );
187: 
188:         
189:         STORE.addRentalSafe(safe);
190: 
191:         
192:         emit Events.RentalSafeDeployment(safe, owners, threshold);
193:     }

```


*GitHub* : [144](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L144-L144)

```solidity
309:     function checkTransaction(
310:         address to,
311:         uint256 value,
312:         bytes memory data,
313:         Enum.Operation operation,
314:         uint256,
315:         uint256,
316:         uint256,
317:         address,
318:         address payable,
319:         bytes memory,
320:         address
321:     ) external override {
322:         
323:         
324:         if (operation == Enum.Operation.DelegateCall && !STORE.whitelistedDelegates(to)) {
325:             revert Errors.GuardPolicy_UnauthorizedDelegateCall(to); // <= FOUND
326:         }
327: 
328:         
329:         if (data.length < 4) {
330:             revert Errors.GuardPolicy_FunctionSelectorRequired(); // <= FOUND
331:         }
332: 
333:         
334:         address hook = STORE.contractToHook(to);
335:         bool isActive = STORE.hookOnTransaction(hook);
336: 
337:         
338:         if (hook != address(0) && isActive) {
339:             _forwardToHook(hook, msg.sender, to, value, data);
340:         }
341:         
342:         else {
343:             _checkTransaction(msg.sender, to, data);
344:         }
345:     }

```


*GitHub* : [325](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L325-L330)

```solidity
32:     function deploy(
33:         bytes32 salt,
34:         bytes memory initCode
35:     ) external payable returns (address deploymentAddress) {
36:         
37:         if (address(bytes20(salt)) != msg.sender) {
38:             revert Errors.Create2Deployer_UnauthorizedSender(msg.sender, salt); // <= FOUND
39:         }
40: 
41:         
42:         address targetDeploymentAddress = getCreate2Address(salt, initCode);
43: 
44:         
45:         if (deployed[targetDeploymentAddress]) {
46:             revert Errors.Create2Deployer_AlreadyDeployed(targetDeploymentAddress, salt); // <= FOUND
47:         }
48: 
49:         
50:         deployed[targetDeploymentAddress] = true;
51: 
52:         
53:         assembly {
54:             deploymentAddress := create2(
55:                 
56:                 callvalue(),
57:                 
58:                 add(initCode, 0x20),
59:                 
60:                 mload(initCode),
61:                 
62:                 salt
63:             )
64:         }
65: 
66:         
67:         if (deploymentAddress != targetDeploymentAddress) {
68:             revert Errors.Create2Deployer_MismatchedDeploymentAddress( // <= FOUND
69:                 targetDeploymentAddress,
70:                 deploymentAddress
71:             );
72:         }
73:     }

```


*GitHub* : [38](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L38-L68)

```solidity
310:     function grantRole(Role role_, address addr_) public onlyAdmin {
311:         
312:         if (hasRole[addr_][role_])
313:             revert Errors.Kernel_AddressAlreadyHasRole(addr_, role_); // <= FOUND
314: 
315:         
316:         ensureValidRole(role_);
317: 
318:         
319:         if (!isRole[role_]) isRole[role_] = true;
320: 
321:         
322:         hasRole[addr_][role_] = true;
323: 
324:         emit Events.RoleGranted(role_, addr_);
325:     }

```


*GitHub* : [313](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L313-L313)

```solidity
333:     function revokeRole(Role role_, address addr_) public onlyAdmin {
334:         
335:         if (!isRole[role_]) revert Errors.Kernel_RoleDoesNotExist(role_); // <= FOUND
336: 
337:         
338:         if (!hasRole[addr_][role_])
339:             revert Errors.Kernel_AddressDoesNotHaveRole(addr_, role_); // <= FOUND
340: 
341:         
342:         hasRole[addr_][role_] = false;
343: 
344:         emit Events.RoleRevoked(role_, addr_);
345:     }

```


*GitHub* : [335](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L335-L339)
### [N-19]<a name="n-19"></a> Functions which are either private or internal should have a preceding _ in their name
Add a preceding underscore to the function name, take care to refactor where there functions are called

*There are 1 instance(s) of this issue:*

```solidity
180:     function getModuleAddress(Keycode keycode_) internal view returns (address) 

```


*GitHub* : [180](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L180-L180)
### [N-20]<a name="n-20"></a> Private and internal state variables should have a preceding _ in their name unless they are constants
Add a preceding underscore to the state variable name, take care to refactor where there variables are read/wrote

*There are 1 instance(s) of this issue:*

```solidity
17: address private immutable original; // <= FOUND

```


*GitHub* : [17](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L17-L17)
### [N-21]<a name="n-21"></a> Contract lines should not be longer than 120 characters for readability
Consider spreading these lines over multiple lines to aid in readability and the support of VIM users everywhere.

*There are 2 instance(s) of this issue:*

```solidity
363:             "RentalOrder(bytes32 seaportOrderHash,Item[] items,Hook[] hooks,uint8 orderType,address lender,address renter,address rentalWallet,uint256 startTimestamp,uint256 endTimestamp)" // <= FOUND

```


*GitHub* : [363](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L363-L363)

```solidity
390:                 "RentPayload(OrderFulfillment fulfillment,OrderMetadata metadata,uint256 expiration,address intendedFulfiller)" // <= FOUND

```


*GitHub* : [390](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L390-L390)
### [N-22]<a name="n-22"></a> Setters should prevent re-setting of the same value
In Solidity, manipulating contract storage comes with significant gas costs. One can optimize gas usage by preventing unnecessary storage updates when the new value is the same as the existing one. If an existing value is the same as the new one, not reassigning it to the storage could potentially save substantial amounts of gas, notably 2900 gas for a 'Gsreset'. This saving may come at the expense of a cold storage load operation ('Gcoldsload'), which costs 2100 gas, or a warm storage access operation ('Gwarmaccess'), which costs 100 gas. Therefore, the gas efficiency of your contract can be significantly improved by adding a check that compares the new value with the current one before any storage update operation. If the values are the same, you can bypass the storage operation, thereby saving gas.

*There are 3 instance(s) of this issue:*

```solidity
173:     function setFee(uint256 feeNumerator) external onlyRole("ADMIN_ADMIN") {
174:         ESCRW.setFee(feeNumerator);
175:     }

```


*GitHub* : [173](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L173-L173)

```solidity
362:     function updateHookPath(address to, address hook) external onlyRole("GUARD_ADMIN") {
363:         STORE.updateHookPath(to, hook);
364:     }

```


*GitHub* : [362](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L362-L362)

```solidity
373:     function updateHookStatus(
374:         address hook,
375:         uint8 bitmap
376:     ) external onlyRole("GUARD_ADMIN") {
377:         STORE.updateHookStatus(hook, bitmap);
378:     }

```


*GitHub* : [373](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L373-L373)
### [N-23]<a name="n-23"></a> Function names should differ to make the code more readable
In Solidity, while function overriding allows for functions with the same name to coexist, it is advisable to avoid this practice to enhance code readability and maintainability. Having multiple functions with the same name, even with different parameters or in inherited contracts, can cause confusion and increase the likelihood of errors during development, testing, and debugging. Using distinct and descriptive function names not only clarifies the purpose and behavior of each function, but also helps prevent unintended function calls or incorrect overriding. By adopting a clear and consistent naming convention, developers can create more comprehensible and maintainable smart contracts.

*There are 18 instance(s) of this issue:*

```solidity
86:     function MODULE_PROXY_INSTANTIATION( // <= FOUND
87:         Kernel kernel_
88:     ) external onlyByProxy onlyUninitialized 

```


*GitHub* : [86](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L86-L86)

```solidity
96:     function VERSION() external pure override returns (uint8 major, uint8 minor)  // <= FOUND

```


*GitHub* : [96](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L96-L96)

```solidity
100:     function VERSION() external pure virtual returns (uint8 major, uint8 minor)  // <= FOUND

```


*GitHub* : [100](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L100-L100)

```solidity
103:     function KEYCODE() public pure override returns (Keycode)  // <= FOUND

```


*GitHub* : [103](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L103-L103)

```solidity
360:     function upgrade(address newImplementation) external onlyByProxy permissioned  // <= FOUND

```


*GitHub* : [360](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L360-L360)

```solidity
369:     function freeze() external onlyByProxy permissioned  // <= FOUND

```


*GitHub* : [369](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L369-L369)

```solidity
334:     function toggleWhitelistDelegate( // <= FOUND
335:         address delegate,
336:         bool isEnabled
337:     ) external onlyByProxy permissioned 

```


*GitHub* : [334](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L334-L334)

```solidity
99:     function toggleWhitelistDelegate( // <= FOUND
100:         address delegate,
101:         bool isEnabled
102:     ) external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [99](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L99-L99)

```solidity
347:     function toggleWhitelistExtension( // <= FOUND
348:         address extension,
349:         bool isEnabled
350:     ) external onlyByProxy permissioned 

```


*GitHub* : [347](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L347-L347)

```solidity
113:     function toggleWhitelistExtension( // <= FOUND
114:         address extension,
115:         bool isEnabled
116:     ) external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [113](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L113-L113)

```solidity
397:     function skim(address token, address to) external onlyByProxy permissioned  // <= FOUND

```


*GitHub* : [397](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L397-L397)

```solidity
164:     function skim(address token, address to) external onlyRole("ADMIN_ADMIN")  // <= FOUND

```


*GitHub* : [164](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L164-L164)

```solidity
380:     function setFee(uint256 feeNumerator) external onlyByProxy permissioned  // <= FOUND

```


*GitHub* : [380](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L380-L380)

```solidity
173:     function setFee(uint256 feeNumerator) external onlyRole("ADMIN_ADMIN")  // <= FOUND

```


*GitHub* : [173](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L173-L173)

```solidity
73:     function configureDependencies() // <= FOUND
74:         external
75:         override
76:         onlyKernel
77:         returns (Keycode[] memory dependencies)
78:     

```


*GitHub* : [73](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L73-L73)

```solidity
148:     function configureDependencies() // <= FOUND
149:         external
150:         virtual
151:         onlyKernel
152:         returns (Keycode[] memory dependencies)
153:     

```


*GitHub* : [148](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L148-L148)

```solidity
94:     function requestPermissions() // <= FOUND
95:         external
96:         view
97:         override
98:         onlyKernel
99:         returns (Permissions[] memory requests)
100:     

```


*GitHub* : [94](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L94-L94)

```solidity
166:     function requestPermissions() // <= FOUND
167:         external
168:         view
169:         virtual
170:         onlyKernel
171:         returns (Permissions[] memory requests)
172:     

```


*GitHub* : [166](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L166-L166)
### [N-24]<a name="n-24"></a> Functions within contracts are not ordered according to the solidity style guide
The following order should be used within contracts

constructor

receive function (if exists)

fallback function (if exists)

external

public

internal

private

Rearrange the contract functions and contructors to fit this ordering

*There are 5 instance(s) of this issue:*

```solidity
37: contract PaymentEscrow is Proxiable, Module, PaymentEscrowBase  // <= FOUND

```


*GitHub* : [37](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L37-L37)

```solidity
66: contract Storage is Proxiable, Module, StorageBase  // <= FOUND

```


*GitHub* : [66](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L66-L66)

```solidity
41: contract Create is Policy, Signer, Zone, Accumulator  // <= FOUND

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L41-L41)

```solidity
39: contract Guard is Policy, BaseGuard  // <= FOUND

```


*GitHub* : [39](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L39-L39)

```solidity
34: contract Stop is Policy, Signer, Reclaimer, Accumulator  // <= FOUND

```


*GitHub* : [34](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L34-L34)
### [N-25]<a name="n-25"></a> Use SafeCast to safely downcast variables
Downcasting int/uints in Solidity can be unsafe due to the potential for data loss and unintended behavior. When downcasting a larger integer type to a smaller one (e.g., uint256 to uint128), the value may exceed the range of the target type, leading to truncation and loss of significant digits. This data loss can result in unexpected state changes, incorrect calculations, or other contract vulnerabilities, ultimately compromising the contracts functionality and reliability. To prevent these risks, developers should carefully consider the range of values their variables may hold and ensure that proper checks are in place to prevent out-of-range values before performing downcasting. Also consider using OZ SafeCast functionality.

*There are 6 instance(s) of this issue:*

```solidity
149:     function hookOnTransaction(address hook) external view returns (bool) {
150:         
151:         return (uint8(1) & hookStatus[hook]) != 0; // <= FOUND
152:     }

```


*GitHub* : [151](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L151-L151)

```solidity
159:     function hookOnStart(address hook) external view returns (bool) {
160:         
161:         return uint8(2) & hookStatus[hook] != 0; // <= FOUND
162:     }

```


*GitHub* : [161](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L161-L161)

```solidity
169:     function hookOnStop(address hook) external view returns (bool) {
170:         
171:         return uint8(4) & hookStatus[hook] != 0; // <= FOUND
172:     }

```


*GitHub* : [171](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L171-L171)

```solidity
313:     function updateHookStatus(
314:         address hook,
315:         uint8 bitmap
316:     ) external onlyByProxy permissioned {
317:         
318:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook);
319: 
320:         
321:         if (bitmap > uint8(7)) // <= FOUND
322:             revert Errors.StorageModule_InvalidHookStatusBitmap(bitmap);
323: 
324:         
325:         hookStatus[hook] = bitmap;
326:     }

```


*GitHub* : [321](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L321-L321)

```solidity
411:     function _convertToItems(
412:         SpentItem[] memory offers,
413:         ReceivedItem[] memory considerations,
414:         OrderType orderType
415:     ) internal pure returns (Item[] memory items) {
416:         
417:         items = new Item[](offers.length + considerations.length);
418: 
419:         
420:         if (orderType.isBaseOrder()) {
421:             
422:             _processBaseOrderOffer(items, offers, 0);
423: 
424:             
425:             _processBaseOrderConsideration(items, considerations, offers.length);
426:         }
427:         
428:         else if (orderType.isPayOrder()) {
429:             
430:             _processPayOrderOffer(items, offers, 0);
431: 
432:             
433:             if (considerations.length > 0) {
434:                 revert Errors.CreatePolicy_ConsiderationCountNonZero(
435:                     considerations.length
436:                 );
437:             }
438:         }
439:         
440:         else if (orderType.isPayeeOrder()) {
441:             
442:             if (offers.length > 0) {
443:                 revert Errors.CreatePolicy_OfferCountNonZero(offers.length);
444:             }
445: 
446:             
447:             _processPayeeOrderConsideration(considerations);
448:         }
449:         
450:         else {
451:             revert Errors.Shared_OrderTypeNotSupported(uint8(orderType)); // <= FOUND
452:         }
453:     }

```


*GitHub* : [451](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L451-L451)

```solidity
84:     function getCreate2Address(
85:         bytes32 salt,
86:         bytes memory initCode
87:     ) public view returns (address) {
88:         
89:         bytes32 addressHash = keccak256(
90:             abi.encodePacked(create2_ff, address(this), salt, keccak256(initCode))
91:         );
92: 
93:         
94:         return address(uint160(uint256(addressHash))); // <= FOUND
95:     }

```


*GitHub* : [94](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L94-L94)
### [N-26]<a name="n-26"></a> Functions which set address state variables should have zero address checks

*There are 3 instance(s) of this issue:*

```solidity
159:     function _settlePaymentProRata(
160:         address token,
161:         uint256 amount,
162:         address lender,
163:         address renter,
164:         uint256 elapsedTime,
165:         uint256 totalTime
166:     ) internal {
167:         
168:         (uint256 renterAmount, uint256 lenderAmount) = _calculatePaymentProRata(
169:             amount,
170:             elapsedTime,
171:             totalTime
172:         );
173: 
174:         
175:         _safeTransfer(token, lender, lenderAmount);
176: 
177:         
178:         _safeTransfer(token, renter, renterAmount);
179:     }

```


*GitHub* : [159](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L159-L159)

```solidity
190:     function _settlePaymentInFull(
191:         address token,
192:         uint256 amount,
193:         SettleTo settleTo,
194:         address lender,
195:         address renter
196:     ) internal {
197:         
198:         address settleToAddress = settleTo == SettleTo.LENDER ? lender : renter;
199: 
200:         
201:         _safeTransfer(token, settleToAddress, amount);
202:     }

```


*GitHub* : [190](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L190-L190)

```solidity
215:     function _settlePayment(
216:         Item[] calldata items,
217:         OrderType orderType,
218:         address lender,
219:         address renter,
220:         uint256 start,
221:         uint256 end
222:     ) internal {
223:         
224:         uint256 elapsedTime = block.timestamp - start;
225:         uint256 totalTime = end - start;
226: 
227:         
228:         bool isRentalOver = elapsedTime >= totalTime;
229: 
230:         
231:         for (uint256 i = 0; i < items.length; ++i) {
232:             
233:             Item memory item = items[i];
234: 
235:             
236:             if (item.isERC20()) {
237:                 
238:                 
239:                 uint256 paymentAmount = item.amount;
240: 
241:                 
242:                 if (fee != 0) {
243:                     
244:                     uint256 paymentFee = _calculateFee(paymentAmount);
245: 
246:                     
247:                     paymentAmount -= paymentFee;
248:                 }
249: 
250:                 
251:                 
252:                 _decreaseDeposit(item.token, item.amount);
253: 
254:                 
255:                 if (orderType.isPayOrder() && !isRentalOver) {
256:                     
257:                     _settlePaymentProRata(
258:                         item.token,
259:                         paymentAmount,
260:                         lender,
261:                         renter,
262:                         elapsedTime,
263:                         totalTime
264:                     );
265:                 }
266:                 
267:                 else if (
268:                     (orderType.isPayOrder() && isRentalOver) || orderType.isBaseOrder()
269:                 ) {
270:                     
271:                     _settlePaymentInFull(
272:                         item.token,
273:                         paymentAmount,
274:                         item.settleTo,
275:                         lender,
276:                         renter
277:                     );
278:                 } else {
279:                     revert Errors.Shared_OrderTypeNotSupported(uint8(orderType));
280:                 }
281:             }
282:         }
283:     }

```


*GitHub* : [215](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L215-L215)
### [N-27]<a name="n-27"></a> Interface imports should be declared first
Amend the ordering of imports to import interfaces first followed by other imports

*There are 4 instance(s) of this issue:*

```solidity
2: 
3: pragma solidity ^0.8.20;
4: 
5: import {SafeL2} from "@safe-contracts/SafeL2.sol"; // <= FOUND
6: import {SafeProxyFactory} from "@safe-contracts/proxies/SafeProxyFactory.sol"; // <= FOUND
7: import {TokenCallbackHandler} from "@safe-contracts/handler/TokenCallbackHandler.sol"; // <= FOUND
8: 
9: import {ISafe} from "@src/interfaces/ISafe.sol"; // <= FOUND
10: 
11: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol"; // <= FOUND
12: import {toKeycode} from "@src/libraries/KernelUtils.sol"; // <= FOUND
13: import {Errors} from "@src/libraries/Errors.sol"; // <= FOUND
14: import {Events} from "@src/libraries/Events.sol"; // <= FOUND
15: import {Storage} from "@src/modules/Storage.sol"; // <= FOUND
16: import {Stop} from "@src/policies/Stop.sol"; // <= FOUND
17: import {Guard} from "@src/policies/Guard.sol"; // <= FOUND
18: 
23: contract Factory is Policy {
24:     
29:     Storage public STORE;
30: 
32:     Stop public immutable stopPolicy;
33:     Guard public immutable guardPolicy;
34: 
36:     TokenCallbackHandler public immutable fallbackHandler;
37:     SafeProxyFactory public immutable safeProxyFactory;
38:     SafeL2 public immutable safeSingleton;
39: 
50:     constructor(
51:         Kernel kernel_,
52:         Stop stopPolicy_,
53:         Guard guardPolicy_,
54:         TokenCallbackHandler fallbackHandler_,
55:         SafeProxyFactory safeProxyFactory_,
56:         SafeL2 safeSingleton_
57:     ) Policy(kernel_) {
58:         stopPolicy = stopPolicy_;
59:         guardPolicy = guardPolicy_;
60:         fallbackHandler = fallbackHandler_;
61:         safeProxyFactory = safeProxyFactory_;
62:         safeSingleton = safeSingleton_;
63:     }
64: 
74:     function configureDependencies()
75:         external
76:         override
77:         onlyKernel
78:         returns (Keycode[] memory dependencies)
79:     {
80:         dependencies = new Keycode[](1);
81: 
82:         dependencies[0] = toKeycode("STORE");
83:         STORE = Storage(getModuleAddress(toKeycode("STORE")));
84:     }
85: 
95:     function requestPermissions()
96:         external
97:         view
98:         override
99:         onlyKernel
100:         returns (Permissions[] memory requests)
101:     {
102:         requests = new Permissions[](1);
103:         requests[0] = Permissions(toKeycode("STORE"), STORE.addRentalSafe.selector);
104:     }

```


*GitHub* : [5](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L5-L17)

```solidity
2: 
3: pragma solidity ^0.8.20;
4: 
5: import {ZoneParameters} from "@seaport-core/lib/rental/ConsiderationStructs.sol"; // <= FOUND
6: import {ReceivedItem, SpentItem} from "@seaport-types/lib/ConsiderationStructs.sol"; // <= FOUND
7: import {LibString} from "@solady/utils/LibString.sol"; // <= FOUND
8: 
9: import {ISafe} from "@src/interfaces/ISafe.sol"; // <= FOUND
10: import {IHook} from "@src/interfaces/IHook.sol"; // <= FOUND
11: import {ZoneInterface} from "@src/interfaces/IZone.sol"; // <= FOUND
12: 
13: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol"; // <= FOUND
14: import {toKeycode, toRole} from "@src/libraries/KernelUtils.sol"; // <= FOUND
15: import {RentalUtils} from "@src/libraries/RentalUtils.sol"; // <= FOUND
16: import {Signer} from "@src/packages/Signer.sol"; // <= FOUND
17: import {Zone} from "@src/packages/Zone.sol"; // <= FOUND
18: import {Accumulator} from "@src/packages/Accumulator.sol"; // <= FOUND
19: import {Storage} from "@src/modules/Storage.sol"; // <= FOUND
20: import {PaymentEscrow} from "@src/modules/PaymentEscrow.sol"; // <= FOUND
21: import { // <= FOUND
22:     RentalOrder,
23:     RentPayload,
24:     SeaportPayload,
25:     Hook,
26:     OrderFulfillment,
27:     OrderMetadata,
28:     OrderType,
29:     Item,
30:     ItemType,
31:     SettleTo,
32:     RentalId,
33:     RentalAssetUpdate
34: } from "@src/libraries/RentalStructs.sol";
35: import {Errors} from "@src/libraries/Errors.sol"; // <= FOUND
36: import {Events} from "@src/libraries/Events.sol"; // <= FOUND
37: 
42: contract Create is Policy, Signer, Zone, Accumulator {
43:     using RentalUtils for Item;
44:     using RentalUtils for Item[];
45:     using RentalUtils for SpentItem;
46:     using RentalUtils for ReceivedItem;
47:     using RentalUtils for OrderType;
48: 
54:     Storage public STORE;
55:     PaymentEscrow public ESCRW;
56: 
62:     constructor(Kernel kernel_) Policy(kernel_) Signer() Zone() {}
63: 
73:     function configureDependencies()
74:         external
75:         override
76:         onlyKernel
77:         returns (Keycode[] memory dependencies)
78:     {
79:         dependencies = new Keycode[](2);
80: 
81:         dependencies[0] = toKeycode("STORE");
82:         STORE = Storage(getModuleAddress(toKeycode("STORE")));
83: 
84:         dependencies[1] = toKeycode("ESCRW");
85:         ESCRW = PaymentEscrow(getModuleAddress(toKeycode("ESCRW")));
86:     }
87: 
97:     function requestPermissions()
98:         external
99:         view
100:         override
101:         onlyKernel
102:         returns (Permissions[] memory requests)
103:     {
104:         requests = new Permissions[](2);
105:         requests[0] = Permissions(toKeycode("STORE"), STORE.addRentals.selector);
106:         requests[1] = Permissions(toKeycode("ESCRW"), ESCRW.increaseDeposit.selector);
107:     }
108: 
118:     function domainSeparator() external view returns (bytes32) {
119:         return _DOMAIN_SEPARATOR;
120:     }
121: 
127:     function getRentalOrderHash(
128:         RentalOrder memory order
129:     ) external view returns (bytes32) {
130:         return _deriveRentalOrderHash(order);
131:     }

```


*GitHub* : [5](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L5-L36)

```solidity
2: 
3: pragma solidity ^0.8.20;
4: 
5: import {Enum} from "@safe-contracts/common/Enum.sol"; // <= FOUND
6: import {LibString} from "@solady/utils/LibString.sol"; // <= FOUND
7: 
8: import {ISafe} from "@src/interfaces/ISafe.sol"; // <= FOUND
9: import {IHook} from "@src/interfaces/IHook.sol"; // <= FOUND
10: 
11: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol"; // <= FOUND
12: import {toKeycode} from "@src/libraries/KernelUtils.sol"; // <= FOUND
13: import {RentalUtils} from "@src/libraries/RentalUtils.sol"; // <= FOUND
14: import {Signer} from "@src/packages/Signer.sol"; // <= FOUND
15: import {Reclaimer} from "@src/packages/Reclaimer.sol"; // <= FOUND
16: import {Accumulator} from "@src/packages/Accumulator.sol"; // <= FOUND
17: import {Storage} from "@src/modules/Storage.sol"; // <= FOUND
18: import {PaymentEscrow} from "@src/modules/PaymentEscrow.sol"; // <= FOUND
19: import {Errors} from "@src/libraries/Errors.sol"; // <= FOUND
20: import {Events} from "@src/libraries/Events.sol"; // <= FOUND
21: import { // <= FOUND
22:     Item,
23:     RentalOrder,
24:     Hook,
25:     OrderType,
26:     ItemType,
27:     RentalId,
28:     RentalAssetUpdate
29: } from "@src/libraries/RentalStructs.sol";
30: 
35: contract Stop is Policy, Signer, Reclaimer, Accumulator {
36:     using RentalUtils for Item;
37:     using RentalUtils for Item[];
38:     using RentalUtils for OrderType;
39: 
45:     Storage public STORE;
46:     PaymentEscrow public ESCRW;
47: 
53:     constructor(Kernel kernel_) Policy(kernel_) Signer() Reclaimer() {}
54: 
64:     function configureDependencies()
65:         external
66:         override
67:         onlyKernel
68:         returns (Keycode[] memory dependencies)
69:     {
70:         dependencies = new Keycode[](2);
71: 
72:         dependencies[0] = toKeycode("STORE");
73:         STORE = Storage(getModuleAddress(toKeycode("STORE")));
74: 
75:         dependencies[1] = toKeycode("ESCRW");
76:         ESCRW = PaymentEscrow(getModuleAddress(toKeycode("ESCRW")));
77:     }
78: 
88:     function requestPermissions()
89:         external
90:         view
91:         override
92:         onlyKernel
93:         returns (Permissions[] memory requests)
94:     {
95:         requests = new Permissions[](4);
96:         requests[0] = Permissions(toKeycode("STORE"), STORE.removeRentals.selector);
97:         requests[1] = Permissions(toKeycode("STORE"), STORE.removeRentalsBatch.selector);
98:         requests[2] = Permissions(toKeycode("ESCRW"), ESCRW.settlePayment.selector);
99:         requests[3] = Permissions(toKeycode("ESCRW"), ESCRW.settlePaymentBatch.selector);
100:     }
101: 
112:     function _emitRentalOrderStopped(bytes32 seaportOrderHash, address stopper) internal {

```


*GitHub* : [5](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L5-L21)

```solidity
2: 
3: pragma solidity ^0.8.20;
4: 
5: import {BaseGuard} from "@safe-contracts/base/GuardManager.sol"; // <= FOUND
6: import {Enum} from "@safe-contracts/common/Enum.sol"; // <= FOUND
7: import {LibString} from "@solady/utils/LibString.sol"; // <= FOUND
8: 
9: import {IHook} from "@src/interfaces/IHook.sol"; // <= FOUND
10: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol"; // <= FOUND
11: import {toKeycode} from "@src/libraries/KernelUtils.sol"; // <= FOUND
12: import {Storage} from "@src/modules/Storage.sol"; // <= FOUND
13: import { // <= FOUND
14:     shared_set_approval_for_all_selector,
15:     e721_approve_selector,
16:     e721_safe_transfer_from_1_selector,
17:     e721_safe_transfer_from_2_selector,
18:     e721_transfer_from_selector,
19:     e721_approve_token_id_offset,
20:     e721_safe_transfer_from_1_token_id_offset,
21:     e721_safe_transfer_from_2_token_id_offset,
22:     e721_transfer_from_token_id_offset,
23:     e1155_safe_transfer_from_selector,
24:     e1155_safe_batch_transfer_from_selector,
25:     e1155_safe_transfer_from_token_id_offset,
26:     e1155_safe_batch_transfer_from_token_id_offset,
27:     gnosis_safe_set_guard_selector,
28:     gnosis_safe_enable_module_selector,
29:     gnosis_safe_disable_module_selector,
30:     gnosis_safe_enable_module_offset,
31:     gnosis_safe_disable_module_offset
32: } from "@src/libraries/RentalConstants.sol";
33: import {Errors} from "@src/libraries/Errors.sol"; // <= FOUND
34: 
40: contract Guard is Policy, BaseGuard {
41:     
46:     Storage public STORE;
47: 
53:     constructor(Kernel kernel_) Policy(kernel_) {}
54: 
64:     function configureDependencies()
65:         external
66:         override
67:         onlyKernel
68:         returns (Keycode[] memory dependencies)
69:     {
70:         dependencies = new Keycode[](1);
71: 
72:         dependencies[0] = toKeycode("STORE");
73:         STORE = Storage(getModuleAddress(toKeycode("STORE")));
74:     }
75: 
85:     function requestPermissions()
86:         external
87:         view
88:         override
89:         onlyKernel
90:         returns (Permissions[] memory requests)
91:     {
92:         requests = new Permissions[](2);
93:         requests[0] = Permissions(toKeycode("STORE"), STORE.updateHookPath.selector);
94:         requests[1] = Permissions(toKeycode("STORE"), STORE.updateHookStatus.selector);
95:     }
96: 
109:     function _loadValueFromCalldata(
110:         bytes memory data,
111:         uint256 offset
112:     ) private pure returns (bytes32 value) {
113:         
114:         assembly {
115:             value := mload(add(data, offset))
116:         }
117:     }
118: 
127:     function _revertSelectorOnActiveRental(
128:         bytes4 selector,
129:         address safe,
130:         address token,
131:         uint256 tokenId
132:     ) private view {
133:         
134:         if (STORE.isRentedOut(safe, token, tokenId)) {

```


*GitHub* : [5](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L5-L33)
### [N-28]<a name="n-28"></a> A function which defines named returns in it's declaration doesn't need to use return 
Remove the return statement once ensuring it is safe to do so

*There are 1 instance(s) of this issue:*

```solidity
96:     function VERSION() external pure override returns (uint8 major, uint8 minor) {
97:         return (1, 0); // <= FOUND
98:     }

```


*GitHub* : [97](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L97-L97)
### [N-29]<a name="n-29"></a> Use allowlist/denylist rather than whitelist/blacklist

*There are 16 instance(s) of this issue:*

```solidity
55: 
62:     mapping(address delegate => bool isWhitelisted) public whitelistedDelegates; // <= FOUND

```


*GitHub* : [62](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L62-L62)

```solidity
58: 
60:     mapping(address extension => bool isWhitelisted) public whitelistedExtensions; // <= FOUND

```


*GitHub* : [60](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L60-L60)

```solidity
338:         whitelistedDelegates[delegate] = isEnabled; // <= FOUND

```


*GitHub* : [338](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L338-L338)

```solidity
351:         whitelistedExtensions[extension] = isEnabled; // <= FOUND

```


*GitHub* : [351](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L351-L351)

```solidity
145:         
146:         if (!STORE.whitelistedExtensions(extension)) { // <= FOUND

```


*GitHub* : [146](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L146-L146)

```solidity
324:         
325:         
326:         if (operation == Enum.Operation.DelegateCall && !STORE.whitelistedDelegates(to)) { // <= FOUND

```


*GitHub* : [326](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L326-L326)

```solidity
334: 
341:     function toggleWhitelistDelegate( // <= FOUND
342:         address delegate,
343:         bool isEnabled
344:     ) external onlyByProxy permissioned {

```


*GitHub* : [341](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L341-L341)

```solidity
347: 
354:     function toggleWhitelistExtension( // <= FOUND
355:         address extension,
356:         bool isEnabled
357:     ) external onlyByProxy permissioned {

```


*GitHub* : [354](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L354-L354)

```solidity
72:         requests[0] = Permissions(
73:             toKeycode("STORE"),
74:             STORE.toggleWhitelistExtension.selector // <= FOUND
75:         );

```


*GitHub* : [74](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L74-L74)

```solidity
76:         requests[1] = Permissions(
77:             toKeycode("STORE"),
78:             STORE.toggleWhitelistDelegate.selector // <= FOUND
79:         );

```


*GitHub* : [78](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L78-L78)

```solidity
99: 
110:     function toggleWhitelistDelegate( // <= FOUND
111:         address delegate,
112:         bool isEnabled
113:     ) external onlyRole("ADMIN_ADMIN") {

```


*GitHub* : [110](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L110-L110)

```solidity
103:         STORE.toggleWhitelistDelegate(delegate, isEnabled); // <= FOUND

```


*GitHub* : [103](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L103-L103)

```solidity
113: 
121:     function toggleWhitelistExtension( // <= FOUND
122:         address extension,
123:         bool isEnabled
124:     ) external onlyRole("ADMIN_ADMIN") {

```


*GitHub* : [121](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L121-L121)

```solidity
117:         STORE.toggleWhitelistExtension(extension, isEnabled); // <= FOUND

```


*GitHub* : [117](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L117-L117)

```solidity
143: 
149:     function _revertNonWhitelistedExtension(address extension) private view { // <= FOUND

```


*GitHub* : [149](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L149-L149)

```solidity
254: 
255:             
256:             _revertNonWhitelistedExtension(extension); // <= FOUND

```


*GitHub* : [256](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L256-L256)
### [N-30]<a name="n-30"></a> Multiple mappings can be replaced with a single struct mapping
Using a single struct mapping in place of multiple defined mappings in a Solidity contract can lead to improved code organization, better readability, and easier maintainability. By consolidating related data into a single struct, developers can create a more cohesive data structure that logically groups together relevant pieces of information, thus reducing redundancy and clutter. This approach simplifies the codebase, making it easier to understand, navigate, and modify. Additionally, it can result in more efficient gas usage when accessing or updating multiple related data points simultaneously.

*There are 2 instance(s) of this issue:*

```solidity
14: contract StorageBase {
15:     
20:     mapping(bytes32 orderHash => bool isActive) public orders; // <= FOUND
21: 
26:     mapping(RentalId itemId => uint256 amount) public rentedAssets; // <= FOUND
27: 
33:     mapping(address safe => uint256 nonce) public deployedSafes; // <= FOUND
34: 
36:     uint256 public totalSafes;
37: 
44:     mapping(address to => address hook) internal _contractToHook; // <= FOUND
45: 
47:     mapping(address hook => uint8 enabled) public hookStatus; // <= FOUND
48: 
55:     mapping(address delegate => bool isWhitelisted) public whitelistedDelegates; // <= FOUND
56: 
58:     mapping(address extension => bool isWhitelisted) public whitelistedExtensions; // <= FOUND
59: }

```


*GitHub* : [20](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L20-L58)

```solidity
206: contract Kernel {
207:     
208:     address public executor;
209:     address public admin;
210: 
212:     Keycode[] public allKeycodes;
213:     mapping(Keycode => Module) public getModuleForKeycode;  // <= FOUND
214:     mapping(Module => Keycode) public getKeycodeForModule;  // <= FOUND
215: 
217:     mapping(Keycode => Policy[]) public moduleDependents; // <= FOUND
218:     mapping(Keycode => mapping(Policy => uint256)) public getDependentIndex; // <= FOUND
219: 
221:     mapping(Keycode => mapping(Policy => mapping(bytes4 => bool))) // <= FOUND
222:         public modulePermissions; 
223: 
225:     Policy[] public activePolicies;
226:     mapping(Policy => uint256) public getPolicyIndex; // <= FOUND
227: 
229:     mapping(address => mapping(Role => bool)) public hasRole; // <= FOUND
230:     mapping(Role => bool) public isRole; // <= FOUND
231: 
362: }

```


*GitHub* : [213](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L213-L230)
### [N-31]<a name="n-31"></a> Constants should be on the left side of the 
Putting constants on the left side of a comparison operator like `==` or `<` is a best practice known as "Yoda conditions", which can help prevent accidental assignment instead of comparison. In some programming languages, if a variable is mistakenly put on the left with a single `=` instead of `==`, it assigns the constant's value to the variable without any compiler error. However, doing this with the constant on the left would generate an error, as constants cannot be assigned values. Although Solidity's static typing system prevents accidental assignments within conditionals, adopting this practice enhances code readability and consistency, especially when developers are working across multiple languages that support this convention.

*There are 16 instance(s) of this issue:*

```solidity
115:         if (!success || (data.length != 0 && !abi.decode(data, (bool))))  // <= FOUND

```


*GitHub* : [115](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L115-L115)

```solidity
366:         if (amount == 0)  // <= FOUND

```


*GitHub* : [366](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L366-L366)

```solidity
201:         if (offers.length == 0)  // <= FOUND

```


*GitHub* : [201](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L201-L201)

```solidity
311:         if (totalRentals == 0 || totalPayments == 0)  // <= FOUND

```


*GitHub* : [311](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L311-L311)

```solidity
332:         if (considerations.length == 0)  // <= FOUND

```


*GitHub* : [332](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L332-L332)

```solidity
631:         if (metadata.rentDuration == 0)  // <= FOUND

```


*GitHub* : [631](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L631-L631)

```solidity
649:         if (STORE.deployedSafes(safe) == 0)  // <= FOUND

```


*GitHub* : [649](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L649-L649)

```solidity
143:         if (threshold == 0 || threshold > owners.length)  // <= FOUND

```


*GitHub* : [143](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L143-L143)

```solidity
242:                 if (fee != 0)  // <= FOUND

```


*GitHub* : [242](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L242-L242)

```solidity
433:             if (considerations.length > 0)  // <= FOUND

```


*GitHub* : [433](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L433-L433)

```solidity
442:             if (offers.length > 0)  // <= FOUND

```


*GitHub* : [442](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L442-L442)

```solidity
288:         if (order.hooks.length > 0)  // <= FOUND

```


*GitHub* : [288](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L288-L288)

```solidity
606:             if (payload.metadata.hooks.length > 0)  // <= FOUND

```


*GitHub* : [606](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L606-L606)

```solidity
348:             if (orders[i].hooks.length > 0)  // <= FOUND

```


*GitHub* : [348](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L348-L348)

```solidity
382:         if (feeNumerator > 10000)  // <= FOUND

```


*GitHub* : [382](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L382-L382)

```solidity
329:         if (data.length < 4)  // <= FOUND

```


*GitHub* : [329](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L329-L329)
### [N-32]<a name="n-32"></a> Defined named returns not used within function 
Such instances can be replaced with unnamed returns

*There are 2 instance(s) of this issue:*

```solidity
96:     function VERSION() external pure override returns (uint8 major, uint8 minor) { // <= FOUND
97:         return (1, 0);
98:     }

```


*GitHub* : [96](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L96-L96)

```solidity
100:     function VERSION() external pure virtual returns (uint8 major, uint8 minor) {} // <= FOUND

```


*GitHub* : [100](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L100-L100)
### [N-33]<a name="n-33"></a> Both immutable and constant state variables should be CONSTANT_CASE
Make found instants CAPITAL_CASE

*There are 7 instance(s) of this issue:*

```solidity
19: bytes1 constant create2_ff = 0xff; // <= FOUND

```


*GitHub* : [19](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L19-L19)

```solidity
32: Guard public immutable guardPolicy; // <= FOUND

```


*GitHub* : [32](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L32-L32)

```solidity
35: TokenCallbackHandler public immutable fallbackHandler; // <= FOUND

```


*GitHub* : [35](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L35-L35)

```solidity
36: SafeProxyFactory public immutable safeProxyFactory; // <= FOUND

```


*GitHub* : [36](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L36-L36)

```solidity
37: SafeL2 public immutable safeSingleton; // <= FOUND

```


*GitHub* : [37](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L37-L37)

```solidity
17: address private immutable original; // <= FOUND

```


*GitHub* : [17](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L17-L17)

```solidity
31: Stop public immutable stopPolicy; // <= FOUND

```


*GitHub* : [31](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L31-L31)
### [N-34]<a name="n-34"></a> Consider using named mappings
In Solidity version 0.8.18 and beyond mapping parameters can be named. This makes the purpose and function of a given mapping far clearer which in turn improves readability.

*There are 6 instance(s) of this issue:*

```solidity
16:     mapping(address => bool) public deployed; // <= FOUND

```


*GitHub* : [16](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L16-L16)

```solidity
221:     mapping(Keycode => mapping(Policy => mapping(bytes4 => bool))) // <= FOUND

```


*GitHub* : [221](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L221-L221)

```solidity
229:     mapping(address => mapping(Role => bool)) public hasRole; // <= FOUND

```


*GitHub* : [229](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L229-L229)

```solidity
230:     mapping(Role => bool) public isRole; // <= FOUND

```


*GitHub* : [230](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L230-L230)

```solidity
218:     mapping(Keycode => mapping(Policy => uint256)) public getDependentIndex; // <= FOUND

```


*GitHub* : [218](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L218-L218)

```solidity
226:     mapping(Policy => uint256) public getPolicyIndex; // <= FOUND

```


*GitHub* : [226](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L226-L226)
### [N-35]<a name="n-35"></a> Uses of EIP712 does not include a salt
It is standard for uses of EIP712 to include a salt, not doing so can cause future incompatibilities and in this instance cause hash collisions do to no salting

*There are 1 instance(s) of this issue:*

```solidity
315: 
316:         
317:         eip712DomainTypehash = keccak256(
318:             abi.encodePacked(
319:                 "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)" // <= FOUND
320:             )
321:         );

```


*GitHub* : [315](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L315-L319)
### [N-36]<a name="n-36"></a> Loss of precision
Dividing by large numbers in Solidity can cause a loss of precision due to the language's inherent integer division behavior. Solidity does not support floating-point arithmetic, and as a result, division between integers yields an integer result, truncating any fractional part. When dividing by a large number, the resulting value may become significantly smaller, leading to a loss of precision, as the fractional part is discarded.

*There are 1 instance(s) of this issue:*

```solidity
132:     function _calculatePaymentProRata(
133:         uint256 amount,
134:         uint256 elapsedTime,
135:         uint256 totalTime
136:     ) internal pure returns (uint256 renterAmount, uint256 lenderAmount) {
137:         
138:         uint256 numerator = (amount * elapsedTime) * 1000;
139: 
140:         
141:         
142:         renterAmount = ((numerator / totalTime) + 500) / 1000;
143: 
144:         
145:         lenderAmount = amount - renterAmount;
146:     }

```


*GitHub* : [132](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L132-L132)
### [N-37]<a name="n-37"></a> Use a single contract or library for system wide constants

*There are 1 instance(s) of this issue:*

```solidity
14: contract Create2Deployer {
15:     
16:     mapping(address => bool) public deployed;
17: 
19:     bytes1 constant create2_ff = 0xff; // <= FOUND
20: 
56: }

```


*GitHub* : [19](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L19-L19)
### [N-38]<a name="n-38"></a> Consider using modifiers for address control
Modifiers in Solidity can improve code readability and modularity by encapsulating repetitive checks, such as address validity checks, into a reusable construct. For example, an `onlyOwner` modifier can be used to replace repetitive `require(msg.sender == owner)` checks across several functions, reducing code redundancy and enhancing maintainability. To implement, define a modifier with the check, then apply the modifier to relevant functions.

*There are 1 instance(s) of this issue:*

```solidity
135: 
136:         
137:         bool isLender = expectedLender == msg.sender; // <= FOUND

```


*GitHub* : [135](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L135-L137)
### [N-39]<a name="n-39"></a> Default address(0) can be returned
Allowing a function in Solidity to return the default address (address(0)) can be problematic as it can represent uninitialized or invalid addresses. If such an address is utilized in transfer operations or other sensitive actions, it could lead to loss of funds or unpredicted behavior. It's prudent to include checks in your functions to prevent the return of the zero address, enhancing contract security.

*There are 3 instance(s) of this issue:*

```solidity
135:     function contractToHook(address to) external view returns (address) {
136:         
137:         address hook = _contractToHook[to];
138: 
139:         
140:         
141:         return hookStatus[hook] != 0 ? hook : address(0);
142:     }

```


*GitHub* : [135](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L135-L135)

```solidity
107:     function _recoverSignerFromPayload(
108:         bytes32 payloadHash,
109:         bytes memory signature
110:     ) internal view returns (address) {
111:         
112:         bytes32 digest = _DOMAIN_SEPARATOR.toTypedDataHash(payloadHash);
113: 
114:         
115:         return digest.recover(signature);
116:     }

```


*GitHub* : [107](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L107-L107)

```solidity
84:     function getCreate2Address(
85:         bytes32 salt,
86:         bytes memory initCode
87:     ) public view returns (address) {
88:         
89:         bytes32 addressHash = keccak256(
90:             abi.encodePacked(create2_ff, address(this), salt, keccak256(initCode))
91:         );
92: 
93:         
94:         return address(uint160(uint256(addressHash)));
95:     }

```


*GitHub* : [84](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L84-L84)
### [N-40]<a name="n-40"></a> Variables should be used in place of magic numbers to improve readability
Magic numbers should be avoided in Solidity code to enhance readability, maintainability, and reduce the likelihood of errors. Magic numbers are hard-coded values with no clear meaning or context, which can create confusion and make the code harder to understand for developers. Using well-defined constants or variables with descriptive names instead of magic numbers not only clarifies the purpose and significance of the value but also simplifies code updates and modifications.

*There are 5 instance(s) of this issue:*

```solidity
90:         
91:         return (amount * fee) / 10000; // <= FOUND

```


*GitHub* : [90](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L90-L91)

```solidity
138:         
139:         uint256 numerator = (amount * elapsedTime) * 1000; // <= FOUND

```


*GitHub* : [138](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L138-L139)

```solidity
142: 
143:         
144:         
145:         renterAmount = ((numerator / totalTime) + 500) / 1000; // <= FOUND

```


*GitHub* : [142](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L142-L145)

```solidity
382:         
383:         if (feeNumerator > 10000) { // <= FOUND

```


*GitHub* : [382](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L382-L383)

```solidity
329: 
330:         
331:         if (data.length < 4) { // <= FOUND

```


*GitHub* : [329](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L329-L331)
### [N-41]<a name="n-41"></a> Long powers of ten should use scientific notation 1eX
A large number such as 1000000 is far more readable as 1e6, this will help prevent unintended bugs in the code

*There are 4 instance(s) of this issue:*

```solidity
90:         
91:         return (amount * fee) / 10000; // <= FOUND

```


*GitHub* : [91](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L91-L91)

```solidity
138:         
139:         uint256 numerator = (amount * elapsedTime) * 1000; // <= FOUND

```


*GitHub* : [139](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L139-L139)

```solidity
142: 
143:         
144:         
145:         renterAmount = ((numerator / totalTime) + 500) / 1000; // <= FOUND

```


*GitHub* : [145](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L145-L145)

```solidity
382:         
383:         if (feeNumerator > 10000) { // <= FOUND

```


*GitHub* : [383](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L383-L383)
### [N-42]<a name="n-42"></a> Use EIP-5767 to manage EIP712 domains

*There are 1 instance(s) of this issue:*

```solidity
315: 
316:         
317:         eip712DomainTypehash = keccak256(
318:             abi.encodePacked(
319:                 "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)" // <= FOUND
320:             )
321:         );

```


*GitHub* : [319](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L319-L319)
### [N-43]<a name="n-43"></a> Overridden function has no body
In Ethereum Solidity, functions can be overridden, meaning a contract can change the behavior of a function inherited from a base contract. Sometimes, the overriding function might not have a body. This could be due to a variety of reasons. For instance, the overriding function could be setting up a default behavior (like failing with an error) that can be further overridden in derived contracts, or it could be providing an optional hook that's left empty unless certain specific conditions are met.

In such cases, it can be extremely helpful to future developers, auditors, and users of the contract if a NatSpec comment is added to describe the function's purpose and the reason why it does not have a body. NatSpec, short for Natural Specification, is a form of documentation standard in Ethereum used for expressing what a function does in a human-readable format.

*There are 1 instance(s) of this issue:*

```solidity
353:     function checkAfterExecution(bytes32 txHash, bool success) external override {}

```


*GitHub* : [353](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L353-L353)
### [N-44]<a name="n-44"></a> Empty bytes check is missing
When developing smart contracts in Solidity, it's crucial to validate the inputs of your functions. This includes ensuring that the bytes parameters are not empty, especially when they represent crucial data such as addresses, identifiers, or raw data that the contract needs to process.

Missing empty bytes checks can lead to unexpected behaviour in your contract. For instance, certain operations might fail, produce incorrect results, or consume unnecessary gas when performed with empty bytes. Moreover, missing input validation can potentially expose your contract to malicious activity, including exploitation of unhandled edge cases.

To mitigate these issues, always validate that bytes parameters are not empty when the logic of your contract requires it.

*There are 12 instance(s) of this issue:*

```solidity
32:     function _insert(
33:         bytes memory rentalAssets,
34:         RentalId rentalId,
35:         uint256 rentalAssetAmount
36:     ) internal pure {
37:         
38:         bytes32 _rentalId = RentalId.unwrap(rentalId);
39: 
40:         assembly {
41:             
42:             if eq(mload(rentalAssets), 0) {
43:                 
44:                 mstore(rentalAssets, 0x20)
45: 
46:                 
47:                 mstore(add(0x20, rentalAssets), 0x00)
48:             }
49: 
50:             
51:             
52:             let newByteDataSize := add(mload(rentalAssets), 0x40)
53: 
54:             
55:             let rentalAssetElementPtr := add(rentalAssets, 0x20)
56: 
57:             
58:             let elements := add(mload(rentalAssetElementPtr), 1)
59: 
60:             
61:             
62:             
63:             
64:             let newItemPosition := add(
65:                 rentalAssetElementPtr,
66:                 sub(mul(elements, 0x40), 0x20)
67:             )
68: 
69:             
70:             mstore(rentalAssets, newByteDataSize)
71: 
72:             
73:             mstore(rentalAssetElementPtr, elements)
74: 
75:             
76:             mstore(newItemPosition, _rentalId)
77: 
78:             
79:             mstore(add(newItemPosition, 0x20), rentalAssetAmount)
80: 
81:             
82:             
83:             mstore(0x40, add(newItemPosition, 0x40))
84:         }
85:     }

```


*GitHub* : [32](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L32-L32)

```solidity
96:     function _convertToStatic(
97:         bytes memory rentalAssetUpdates
98:     ) internal pure returns (RentalAssetUpdate[] memory updates) {
99:         
100:         bytes32 rentalAssetUpdatePointer;
101: 
102:         
103:         uint256 rentalAssetUpdateLength;
104:         assembly {
105:             
106:             
107:             
108:             
109:             rentalAssetUpdatePointer := add(0x20, rentalAssetUpdates)
110: 
111:             
112:             rentalAssetUpdateLength := mload(rentalAssetUpdatePointer)
113:         }
114: 
115:         
116:         updates = new RentalAssetUpdate[](rentalAssetUpdateLength);
117: 
118:         
119:         
120:         for (uint256 i = 0; i < rentalAssetUpdateLength; ++i) {
121:             
122:             RentalId rentalId;
123:             uint256 amount;
124: 
125:             
126:             assembly {
127:                 
128:                 
129:                 
130:                 
131:                 let currentElementOffset := add(0x20, mul(i, 0x40))
132: 
133:                 
134:                 rentalId := mload(add(rentalAssetUpdatePointer, currentElementOffset))
135: 
136:                 
137:                 amount := mload(
138:                     add(0x20, add(rentalAssetUpdatePointer, currentElementOffset))
139:                 )
140:             }
141: 
142:             
143:             updates[i] = RentalAssetUpdate(rentalId, amount);
144:         }
145:     }

```


*GitHub* : [96](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L96-L96)

```solidity
107:     function _recoverSignerFromPayload(
108:         bytes32 payloadHash,
109:         bytes memory signature
110:     ) internal view returns (address) {
111:         
112:         bytes32 digest = _DOMAIN_SEPARATOR.toTypedDataHash(payloadHash);
113: 
114:         
115:         return digest.recover(signature);
116:     }

```


*GitHub* : [107](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L107-L107)

```solidity
273:     function _deriveDomainSeparator(
274:         bytes32 _eip712DomainTypeHash,
275:         bytes32 _nameHash,
276:         bytes32 _versionHash
277:     ) internal view virtual returns (bytes32) {
278:         return
279:             keccak256(
280:                 abi.encode(
281:                     _eip712DomainTypeHash,
282:                     _nameHash,
283:                     _versionHash,
284:                     block.chainid,
285:                     address(this)
286:                 )
287:             );
288:     }

```


*GitHub* : [273](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L273-L273)

```solidity
165:     function _emitRentalOrderStarted(
166:         RentalOrder memory order,
167:         bytes32 orderHash,
168:         bytes memory extraData
169:     ) internal {
170:         
171:         emit Events.RentalOrderStarted(
172:             orderHash,
173:             extraData,
174:             order.seaportOrderHash,
175:             order.items,
176:             order.hooks,
177:             order.orderType,
178:             order.lender,
179:             order.renter,
180:             order.rentalWallet,
181:             order.startTimestamp,
182:             order.endTimestamp
183:         );
184:     }

```


*GitHub* : [165](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L165-L165)

```solidity
626:     function _isValidOrderMetadata(
627:         OrderMetadata memory metadata,
628:         bytes32 zoneHash
629:     ) internal view {
630:         
631:         if (metadata.rentDuration == 0) {
632:             revert Errors.CreatePolicy_RentDurationZero();
633:         }
634: 
635:         
636:         if (_deriveOrderMetadataHash(metadata) != zoneHash) {
637:             revert Errors.CreatePolicy_InvalidOrderMetadataHash();
638:         }
639:     }

```


*GitHub* : [626](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L626-L626)

```solidity
126:     function _revertSelectorOnActiveRental(
127:         bytes4 selector,
128:         address safe,
129:         address token,
130:         uint256 tokenId
131:     ) private view {
132:         
133:         if (STORE.isRentedOut(safe, token, tokenId)) {
134:             revert Errors.GuardPolicy_UnauthorizedSelector(selector);
135:         }
136:     }

```


*GitHub* : [126](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L126-L126)

```solidity
159:     function _forwardToHook(
160:         address hook,
161:         address safe,
162:         address to,
163:         uint256 value,
164:         bytes memory data
165:     ) private {
166:         
167:         try IHook(hook).onTransaction(safe, to, value, data) {} catch Error(
168:             string memory revertReason
169:         ) {
170:             
171:             revert Errors.Shared_HookFailString(revertReason);
172:         } catch Panic(uint256 errorCode) {
173:             
174:             string memory stringErrorCode = LibString.toString(errorCode);
175: 
176:             
177:             revert Errors.Shared_HookFailString(
178:                 string.concat("Hook reverted: Panic code ", stringErrorCode)
179:             );
180:         } catch (bytes memory revertData) {
181:             
182:             revert Errors.Shared_HookFailBytes(revertData);
183:         }
184:     }

```


*GitHub* : [159](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L159-L159)

```solidity
195:     function _checkTransaction(address from, address to, bytes memory data) private view {
196:         bytes4 selector;
197: 
198:         
199:         assembly {
200:             selector := mload(add(data, 0x20))
201:         }
202: 
203:         if (selector == e721_safe_transfer_from_1_selector) {
204:             
205:             uint256 tokenId = uint256(
206:                 _loadValueFromCalldata(data, e721_safe_transfer_from_1_token_id_offset)
207:             );
208: 
209:             
210:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
211:         } else if (selector == e721_safe_transfer_from_2_selector) {
212:             
213:             uint256 tokenId = uint256(
214:                 _loadValueFromCalldata(data, e721_safe_transfer_from_2_token_id_offset)
215:             );
216: 
217:             
218:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
219:         } else if (selector == e721_transfer_from_selector) {
220:             
221:             uint256 tokenId = uint256(
222:                 _loadValueFromCalldata(data, e721_transfer_from_token_id_offset)
223:             );
224: 
225:             
226:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
227:         } else if (selector == e721_approve_selector) {
228:             
229:             uint256 tokenId = uint256(
230:                 _loadValueFromCalldata(data, e721_approve_token_id_offset)
231:             );
232: 
233:             
234:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
235:         } else if (selector == e1155_safe_transfer_from_selector) {
236:             
237:             uint256 tokenId = uint256(
238:                 _loadValueFromCalldata(data, e1155_safe_transfer_from_token_id_offset)
239:             );
240: 
241:             
242:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
243:         } else if (selector == gnosis_safe_enable_module_selector) {
244:             
245:             address extension = address(
246:                 uint160(
247:                     uint256(
248:                         _loadValueFromCalldata(data, gnosis_safe_enable_module_offset)
249:                     )
250:                 )
251:             );
252: 
253:             
254:             _revertNonWhitelistedExtension(extension);
255:         } else if (selector == gnosis_safe_disable_module_selector) {
256:             
257:             address extension = address(
258:                 uint160(
259:                     uint256(
260:                         _loadValueFromCalldata(data, gnosis_safe_disable_module_offset)
261:                     )
262:                 )
263:             );
264: 
265:             
266:             _revertNonWhitelistedExtension(extension);
267:         } else {
268:             
269:             
270:             if (selector == shared_set_approval_for_all_selector) {
271:                 revert Errors.GuardPolicy_UnauthorizedSelector(
272:                     shared_set_approval_for_all_selector
273:                 );
274:             }
275: 
276:             
277:             
278:             
279:             
280:             if (selector == e1155_safe_batch_transfer_from_selector) {
281:                 revert Errors.GuardPolicy_UnauthorizedSelector(
282:                     e1155_safe_batch_transfer_from_selector
283:                 );
284:             }
285: 
286:             
287:             if (selector == gnosis_safe_set_guard_selector) {
288:                 revert Errors.GuardPolicy_UnauthorizedSelector(
289:                     gnosis_safe_set_guard_selector
290:                 );
291:             }
292:         }
293:     }

```


*GitHub* : [195](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L195-L195)

```solidity
111:     function _emitRentalOrderStopped(bytes32 seaportOrderHash, address stopper) internal {
112:         
113:         emit Events.RentalOrderStopped(seaportOrderHash, stopper);
114:     }

```


*GitHub* : [111](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L111-L111)

```solidity
32:     function deploy(
33:         bytes32 salt,
34:         bytes memory initCode
35:     ) external payable returns (address deploymentAddress) {
36:         
37:         if (address(bytes20(salt)) != msg.sender) {
38:             revert Errors.Create2Deployer_UnauthorizedSender(msg.sender, salt);
39:         }
40: 
41:         
42:         address targetDeploymentAddress = getCreate2Address(salt, initCode);
43: 
44:         
45:         if (deployed[targetDeploymentAddress]) {
46:             revert Errors.Create2Deployer_AlreadyDeployed(targetDeploymentAddress, salt);
47:         }
48: 
49:         
50:         deployed[targetDeploymentAddress] = true;
51: 
52:         
53:         assembly {
54:             deploymentAddress := create2(
55:                 
56:                 callvalue(),
57:                 
58:                 add(initCode, 0x20),
59:                 
60:                 mload(initCode),
61:                 
62:                 salt
63:             )
64:         }
65: 
66:         
67:         if (deploymentAddress != targetDeploymentAddress) {
68:             revert Errors.Create2Deployer_MismatchedDeploymentAddress(
69:                 targetDeploymentAddress,
70:                 deploymentAddress
71:             );
72:         }
73:     }

```


*GitHub* : [32](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L32-L32)

```solidity
84:     function getCreate2Address(
85:         bytes32 salt,
86:         bytes memory initCode
87:     ) public view returns (address) {
88:         
89:         bytes32 addressHash = keccak256(
90:             abi.encodePacked(create2_ff, address(this), salt, keccak256(initCode))
91:         );
92: 
93:         
94:         return address(uint160(uint256(addressHash)));
95:     }

```


*GitHub* : [84](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L84-L84)
### [N-45]<a name="n-45"></a> Consider adding a time delay to upgrade implementation functions
It's often considered a good practice to use a timelock on sensitive functions such as upgrading a contract, especially when these contracts handle user funds or critical system states.

A timelock is a delay period that must pass between when an action (like an upgrade) is scheduled and when it can be executed. This provides a window of time for users or governance participants to observe the proposed change and potentially respond if they disagree with the action.

*There are 3 instance(s) of this issue:*

```solidity
360:     function upgrade(address newImplementation) external onlyByProxy permissioned { // <= FOUND
361:         
362:         _upgrade(newImplementation);
363:     }

```


*GitHub* : [360](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L360-L360)

```solidity
126:     function upgradeStorage(address newImplementation) external onlyRole("ADMIN_ADMIN") { // <= FOUND
127:         STORE.upgrade(newImplementation);
128:     }

```


*GitHub* : [126](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L126-L126)

```solidity
144:     function upgradePaymentEscrow( // <= FOUND
145:         address newImplementation
146:     ) external onlyRole("ADMIN_ADMIN") {
147:         ESCRW.upgrade(newImplementation);
148:     }

```


*GitHub* : [144](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L144-L144)
### [N-46]<a name="n-46"></a> Use scopes sparingly
In Solidity programming, the use of scoped blocks, denoted by `{}` without a preceding control structure like `if`, `for`, etc., allows for the creation of isolated scopes within a function. While this can be useful for managing memory and preventing naming conflicts, it should be used sparingly. Excessive use of these scope blocks can obscure the code's logic flow and make it more difficult to understand, impeding code maintainability. As a best practice, only employ scoped blocks when necessary for memory management or to avoid clear naming conflicts. Otherwise, aim for clarity and simplicity in your code structure for optimal readability and maintainability.

*There are 1 instance(s) of this issue:*

```solidity
377:         { // <= FOUND
378:             
379:             bytes memory orderFulfillmentTypeString = abi.encodePacked(
380:                 "OrderFulfillment(address recipient)"
381:             );
382: 
383:             
384:             bytes memory orderMetadataTypeString = abi.encodePacked(
385:                 "OrderMetadata(uint8 orderType,uint256 rentDuration,Hook[] hooks,bytes emittedExtraData)"
386:             );
387: 
388:             
389:             bytes memory rentPayloadTypeString = abi.encodePacked(
390:                 "RentPayload(OrderFulfillment fulfillment,OrderMetadata metadata,uint256 expiration,address intendedFulfiller)"
391:             );
392: 
393:             
394:             rentPayloadTypeHash = keccak256(
395:                 abi.encodePacked(
396:                     rentPayloadTypeString,
397:                     orderMetadataTypeString,
398:                     orderFulfillmentTypeString
399:                 )
400:             );
401: 
402:             
403:             orderFulfillmentTypeHash = keccak256(orderFulfillmentTypeString);
404: 
405:             
406:             orderMetadataTypeHash = keccak256(orderMetadataTypeString);
407:         }

```


*GitHub* : [377](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L377-L377)
### [N-47]<a name="n-47"></a> No equate comparison checks between to and from address parameters
The function lacks a standard check: it does not validate if the 'to' and 'from' addresses are identical. This omission can lead to unintended outcomes if the same address is used in both parameters. To rectify this, we recommend implementing a comparison check at the beginning of the function. In the context of Solidity, the command `require(to != from, "To and From addresses can't be the same");` could be utilized. This addition will generate an error if the 'to' and 'from' addresses are the same, thereby fortifying the function's robustness and security.

*There are 1 instance(s) of this issue:*

```solidity
195:     function _checkTransaction(address from, address to, bytes memory data) private view { // <= FOUND
196:         bytes4 selector;
197: 
198:         
199:         assembly {
200:             selector := mload(add(data, 0x20))
201:         }
202: 
203:         if (selector == e721_safe_transfer_from_1_selector) {
204:             
205:             uint256 tokenId = uint256(
206:                 _loadValueFromCalldata(data, e721_safe_transfer_from_1_token_id_offset)
207:             );
208: 
209:             
210:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
211:         } else if (selector == e721_safe_transfer_from_2_selector) {
212:             
213:             uint256 tokenId = uint256(
214:                 _loadValueFromCalldata(data, e721_safe_transfer_from_2_token_id_offset)
215:             );
216: 
217:             
218:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
219:         } else if (selector == e721_transfer_from_selector) {
220:             
221:             uint256 tokenId = uint256(
222:                 _loadValueFromCalldata(data, e721_transfer_from_token_id_offset)
223:             );
224: 
225:             
226:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
227:         } else if (selector == e721_approve_selector) {
228:             
229:             uint256 tokenId = uint256(
230:                 _loadValueFromCalldata(data, e721_approve_token_id_offset)
231:             );
232: 
233:             
234:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
235:         } else if (selector == e1155_safe_transfer_from_selector) {
236:             
237:             uint256 tokenId = uint256(
238:                 _loadValueFromCalldata(data, e1155_safe_transfer_from_token_id_offset)
239:             );
240: 
241:             
242:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
243:         } else if (selector == gnosis_safe_enable_module_selector) {
244:             

```


*GitHub* : [195](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L195-L195)
### [N-48]<a name="n-48"></a> Do not use underscore at the end of variable name
Adopting a consistent and clear naming convention enhances code readability and maintainability. In Solidity, appending an underscore at the end of a variable name is unconventional and can lead to confusion. It is generally advisable to stick to accepted naming practices to promote ease of understanding and use.

*There are 7 instance(s) of this issue:*

```solidity
278:         if (action_ == Actions.InstallModule) { // <= FOUND

```


*GitHub* : [278](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L278-L278)

```solidity
282:         } else if (action_ == Actions.UpgradeModule) { // <= FOUND

```


*GitHub* : [282](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L282-L282)

```solidity
286:         } else if (action_ == Actions.ActivatePolicy) { // <= FOUND

```


*GitHub* : [286](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L286-L286)

```solidity
289:         } else if (action_ == Actions.DeactivatePolicy) { // <= FOUND

```


*GitHub* : [289](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L289-L289)

```solidity
292:         } else if (action_ == Actions.MigrateKernel) { // <= FOUND

```


*GitHub* : [292](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L292-L292)

```solidity
295:         } else if (action_ == Actions.ChangeExecutor) { // <= FOUND

```


*GitHub* : [295](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L295-L295)

```solidity
297:         } else if (action_ == Actions.ChangeAdmin) { // <= FOUND

```


*GitHub* : [297](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L297-L297)
### [N-49]<a name="n-49"></a> Consider using SMTChecker
The SMTChecker is a valuable tool for Solidity developers as it helps detect potential vulnerabilities and logical errors in the contract's code. By utilizing Satisfiability Modulo Theories (SMT) solvers, it can reason about the potential states a contract can be in, and therefore, identify conditions that could lead to undesirable behavior. This automatic formal verification can catch issues that might otherwise be missed in manual code reviews or standard testing, enhancing the overall contract's security and reliability.

*There are 12 instance(s) of this issue:*

```solidity
1: // SPDX-License-Identifier: BUSL-1.1
2: pragma solidity ^0.8.20;
3: 
4: import {Errors} from "@src/libraries/Errors.sol";
5: 
6: /**
7:  * @title Create2Deployer
8:  * @notice Deployment contract that uses the init code and a salt to perform a deployment.
9:  *         There is added cross-chain safety as well because a particular salt can only be
10:  *         used if the sender's address is contained within that salt. This prevents a
11:  *         contract on one chain from being deployed by a non-admin account on
12:  *         another chain.
13:  */
14: contract Create2Deployer {
15:     // Determine if an address has already been deployed.
16:     mapping(address => bool) public deployed;
17: 
18:     // Byte used to prevent collision with CREATE.
19:     bytes1 constant create2_ff = 0xff;
20: 
21:     /**
22:      * @notice Deploys a contract using the given salt and init code. Prevents
23:      *         frontrunning of claiming a specific address by asserting that the first
24:      *         20 bytes of the salt matches the sender. This check is especially useful
25:      *         if trying to keep the same deployment addresses across chains.
26:      *
27:      * @param salt     A unique value which must contain the address of the sender.
28:      * @param initCode The init code of the contract to deploy.
29:      *
30:      * @return deploymentAddress The addres of the deployed contract.
31:      */
32:     function deploy(
33:         bytes32 salt,
34:         bytes memory initCode
35:     ) external payable returns (address deploymentAddress) {
36:         // Ensure the salt is valid for the sender.
37:         if (address(bytes20(salt)) != msg.sender) {
38:             revert Errors.Create2Deployer_UnauthorizedSender(msg.sender, salt);
39:         }
40: 
41:         // Determine the target address for contract deployment.
42:         address targetDeploymentAddress = getCreate2Address(salt, initCode);
43: 
44:         // Ensure that a contract hasn't been previously deployed to target address.
45:         if (deployed[targetDeploymentAddress]) {
46:             revert Errors.Create2Deployer_AlreadyDeployed(targetDeploymentAddress, salt);
47:         }
48: 
49:         // Prevent redeploys of contracts at the same address.
50:         deployed[targetDeploymentAddress] = true;
51: 
52:         // Deploy the contract.
53:         assembly {
54:             deploymentAddress := create2(
55:                 // ETH value to pass to the call.
56:                 callvalue(),
57:                 // Init code data.
58:                 add(initCode, 0x20),
59:                 // Init code data length.
60:                 mload(initCode),
61:                 // Unique salt value.
62:                 salt
63:             )
64:         }
65: 
66:         // Check address against target to ensure that deployment was successful.
67:         if (deploymentAddress != targetDeploymentAddress) {
68:             revert Errors.Create2Deployer_MismatchedDeploymentAddress(
69:                 targetDeploymentAddress,
70:                 deploymentAddress
71:             );
72:         }
73:     }
74: 
75:     /**
76:      * @notice Calculate the target address for contract deployment using the
77:      *         salt and init code.
78:      *
79:      * @param salt     A unique value which must contain the address of the sender.
80:      * @param initCode The init code of the contract to deploy.
81:      *
82:      * @return The address that would be generated from the deployment.
83:      */
84:     function getCreate2Address(
85:         bytes32 salt,
86:         bytes memory initCode
87:     ) public view returns (address) {
88:         // Create the address hash.
89:         bytes32 addressHash = keccak256(
90:             abi.encodePacked(create2_ff, address(this), salt, keccak256(initCode))
91:         );
92: 
93:         // Cast the hash to an address.
94:         return address(uint160(uint256(addressHash)));
95:     }
96: 
97:     /**
98:      * @notice Allows the generation of a salt using the sender address.
99:      *         This function ties the deployment sendder to the salt of the CREATE2
100:      *         address so that it cannot be frontrun on a different chain. More details
101:      *         about this can be found here:
102:      *         https://github.com/martinetlee/create2-snippets#method-1-mixing-with-salt
103:      *
104:      * @param sender The address of the deployer.
105:      * @param data   The added data to make the salt unique.
106:      */
107:     function generateSaltWithSender(
108:         address sender,
109:         bytes12 data
110:     ) public pure returns (bytes32 salt) {
111:         assembly {
112:             // Use `or` to combine the bytes20 address and bytes12 data together.
113:             salt := or(
114:                 // Shift the address 12 bytes to the left.
115:                 shl(0x60, sender),
116:                 // Shift the extra data 20 bytes to the right.
117:                 shr(0xA0, data)
118:             )
119:         }
120:     }
121: }
122: 

```


*GitHub* : [1](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L1-L1)

```solidity
1: // SPDX-License-Identifier: BUSL-1.1
2: pragma solidity ^0.8.20;
3: 
4: import {SafeL2} from "@safe-contracts/SafeL2.sol";
5: import {SafeProxyFactory} from "@safe-contracts/proxies/SafeProxyFactory.sol";
6: import {TokenCallbackHandler} from "@safe-contracts/handler/TokenCallbackHandler.sol";
7: 
8: import {ISafe} from "@src/interfaces/ISafe.sol";
9: 
10: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol";
11: import {toKeycode} from "@src/libraries/KernelUtils.sol";
12: import {Errors} from "@src/libraries/Errors.sol";
13: import {Events} from "@src/libraries/Events.sol";
14: import {Storage} from "@src/modules/Storage.sol";
15: import {Stop} from "@src/policies/Stop.sol";
16: import {Guard} from "@src/policies/Guard.sol";
17: 
18: /**
19:  * @title Factory
20:  * @notice Acts as an interface for all behavior related to deploying rental safes.
21:  */
22: contract Factory is Policy {
23:     /////////////////////////////////////////////////////////////////////////////////
24:     //                         Kernel Policy Configuration                         //
25:     /////////////////////////////////////////////////////////////////////////////////
26: 
27:     // Modules that the policy depends on.
28:     Storage public STORE;
29: 
30:     // policies.
31:     Stop public immutable stopPolicy;
32:     Guard public immutable guardPolicy;
33: 
34:     // External contracts.
35:     TokenCallbackHandler public immutable fallbackHandler;
36:     SafeProxyFactory public immutable safeProxyFactory;
37:     SafeL2 public immutable safeSingleton;
38: 
39:     /**
40:      * @dev Instantiate this contract as a policy.
41:      *
42:      * @param kernel_           Address of the kernel contract.
43:      * @param stopPolicy_       Address of the stop policy.
44:      * @param guardPolicy_      Address of the guard policy.
45:      * @param fallbackHandler_  Gnosis safe fallback handler address.
46:      * @param safeProxyFactory_ Gnosis safe proxy factory address.
47:      * @param safeSingleton_    Gnosis safe logic contract address.
48:      */
49:     constructor(
50:         Kernel kernel_,
51:         Stop stopPolicy_,
52:         Guard guardPolicy_,
53:         TokenCallbackHandler fallbackHandler_,
54:         SafeProxyFactory safeProxyFactory_,
55:         SafeL2 safeSingleton_
56:     ) Policy(kernel_) {
57:         stopPolicy = stopPolicy_;
58:         guardPolicy = guardPolicy_;
59:         fallbackHandler = fallbackHandler_;
60:         safeProxyFactory = safeProxyFactory_;
61:         safeSingleton = safeSingleton_;
62:     }
63: 
64:     /**
65:      * @notice Upon policy activation, configures the modules that the policy depends on.
66:      *         If a module is ever upgraded that this policy depends on, the kernel will
67:      *         call this function again to ensure this policy has the current address
68:      *         of the module.
69:      *
70:      * @return dependencies Array of keycodes which represent modules that
71:      *                      this policy depends on.
72:      */
73:     function configureDependencies()
74:         external
75:         override
76:         onlyKernel
77:         returns (Keycode[] memory dependencies)
78:     {
79:         dependencies = new Keycode[](1);
80: 
81:         dependencies[0] = toKeycode("STORE");
82:         STORE = Storage(getModuleAddress(toKeycode("STORE")));
83:     }
84: 
85:     /**
86:      * @notice Upon policy activation, permissions are requested from the kernel to access
87:      *         particular keycode <> function selector pairs. Once these permissions are
88:      *         granted, they do not change and can only be revoked when the policy is
89:      *         deactivated by the kernel.
90:      *
91:      * @return requests Array of keycode <> function selector pairs which represent
92:      *                  permissions for the policy.
93:      */
94:     function requestPermissions()
95:         external
96:         view
97:         override
98:         onlyKernel
99:         returns (Permissions[] memory requests)
100:     {
101:         requests = new Permissions[](1);
102:         requests[0] = Permissions(toKeycode("STORE"), STORE.addRentalSafe.selector);
103:     }
104: 
105:     /////////////////////////////////////////////////////////////////////////////////
106:     //                            External Functions                               //
107:     /////////////////////////////////////////////////////////////////////////////////
108: 
109:     /**
110:      * @notice Initializes a rental safe by setting it up with the stop policy and
111:      *         rental guard during deployment.
112:      *
113:      *          Warning: This function assumes the invariant that delegate call will be
114:      *          disabled or restricted by the guard policy. If delegate call were to be
115:      *          freely allowed, then a safe could call this function after deployment
116:      *          and change the module/guard contacts which would allow transferring
117:      *          of rented assets out of the safe.
118:      *
119:      * @param _stopPolicy  Address of the stop policy to add as a module to the safe.
120:      * @param _guardPolicy Address of the guard policy to add as a guard on the safe.
121:      */
122:     function initializeRentalSafe(address _stopPolicy, address _guardPolicy) external {
123:         // Enable the module.
124:         ISafe(address(this)).enableModule(_stopPolicy);
125: 
126:         // Set the guard.
127:         ISafe(address(this)).setGuard(_guardPolicy);
128:     }
129: 
130:     /**
131:      * @notice Deploys and initializes a rental safe.
132:      *
133:      * @param owners    Array of owner addresses which will have the ability to sign
134:      *                  transactions for the safe.
135:      * @param threshold Number of signatures required to executed a transaction
136:      *                  on the safe.
137:      */
138:     function deployRentalSafe(
139:         address[] calldata owners,
140:         uint256 threshold
141:     ) external returns (address safe) {
142:         // Require that the threshold is valid.
143:         if (threshold == 0 || threshold > owners.length) {
144:             revert Errors.FactoryPolicy_InvalidSafeThreshold(threshold, owners.length);
145:         }
146: 
147:         // Delegate call from the safe so that the rental manager module can be enabled
148:         // right after the safe is deployed.
149:         bytes memory data = abi.encodeCall(
150:             Factory.initializeRentalSafe,
151:             (address(stopPolicy), address(guardPolicy))
152:         );
153: 
154:         // Create gnosis initializer payload.
155:         bytes memory initializerPayload = abi.encodeCall(
156:             ISafe.setup,
157:             (
158:                 // owners array.
159:                 owners,
160:                 // number of signatures needed to execute transactions.
161:                 threshold,
162:                 // Address to direct the payload to.
163:                 address(this),
164:                 // Encoded call to execute.
165:                 data,
166:                 // Fallback manager address.
167:                 address(fallbackHandler),
168:                 // Payment token.
169:                 address(0),
170:                 // Payment amount.
171:                 0,
172:                 // Payment receiver
173:                 payable(address(0))
174:             )
175:         );
176: 
177:         // Deploy a safe proxy using initializer values for the Safe.setup() call
178:         // with a salt nonce that is unique to each chain to guarantee cross-chain
179:         // unique safe addresses.
180:         safe = address(
181:             safeProxyFactory.createProxyWithNonce(
182:                 address(safeSingleton),
183:                 initializerPayload,
184:                 uint256(keccak256(abi.encode(STORE.totalSafes() + 1, block.chainid)))
185:             )
186:         );
187: 
188:         // Store the deployed safe.
189:         STORE.addRentalSafe(safe);
190: 
191:         // Emit the event.
192:         emit Events.RentalSafeDeployment(safe, owners, threshold);
193:     }
194: }
195: 

```


*GitHub* : [1](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L1-L1)

```solidity
1: // SPDX-License-Identifier: BUSL-1.1
2: pragma solidity ^0.8.20;
3: 
4: import {Kernel, Module, Keycode} from "@src/Kernel.sol";
5: import {Proxiable} from "@src/proxy/Proxiable.sol";
6: import {RentalUtils} from "@src/libraries/RentalUtils.sol";
7: import {RentalId, RentalAssetUpdate} from "@src/libraries/RentalStructs.sol";
8: import {Errors} from "@src/libraries/Errors.sol";
9: 
10: /**
11:  * @title StorageBase
12:  * @notice Storage exists in its own base contract to avoid storage slot mismatch during upgrades.
13:  */
14: contract StorageBase {
15:     /////////////////////////////////////////////////////////////////////////////////
16:     //                                Rental Storage                               //
17:     /////////////////////////////////////////////////////////////////////////////////
18: 
19:     // Points an order hash to whether it is active.
20:     mapping(bytes32 orderHash => bool isActive) public orders;
21: 
22:     // Points an item ID to its number of actively rented tokens. This is used to
23:     // determine if an item is actively rented within the protocol. For ERC721, this
24:     // value will always be 1 when actively rented. Any inactive rentals will have a
25:     // value of 0.
26:     mapping(RentalId itemId => uint256 amount) public rentedAssets;
27: 
28:     /////////////////////////////////////////////////////////////////////////////////
29:     //                            Deployed Safe Storage                            //
30:     /////////////////////////////////////////////////////////////////////////////////
31: 
32:     // Records all safes that have been deployed by the protocol.
33:     mapping(address safe => uint256 nonce) public deployedSafes;
34: 
35:     // Records the total amount of deployed safes.
36:     uint256 public totalSafes;
37: 
38:     /////////////////////////////////////////////////////////////////////////////////
39:     //                                 Hook Storage                                //
40:     /////////////////////////////////////////////////////////////////////////////////
41: 
42:     // When interacting with the guard, any contracts that have hooks enabled
43:     // should have the guard logic routed through them.
44:     mapping(address to => address hook) internal _contractToHook;
45: 
46:     // Mapping of a bitmap which denotes the hook functions that are enabled.
47:     mapping(address hook => uint8 enabled) public hookStatus;
48: 
49:     /////////////////////////////////////////////////////////////////////////////////
50:     //                            Whitelist Storage                                //
51:     /////////////////////////////////////////////////////////////////////////////////
52: 
53:     // Allows the safe to delegate call to an approved address. For example, delegate
54:     // call to a contract that would swap out an old gnosis safe module for a new one.
55:     mapping(address delegate => bool isWhitelisted) public whitelistedDelegates;
56: 
57:     // Allows for the safe registration of extensions that can be enabled on a safe.
58:     mapping(address extension => bool isWhitelisted) public whitelistedExtensions;
59: }
60: 
61: /**
62:  * @title Storage
63:  * @notice Module dedicated to maintaining all the storage for the protocol. Includes
64:  *         storage for active rentals, deployed rental safes, hooks, and whitelists.
65:  */
66: contract Storage is Proxiable, Module, StorageBase {
67:     using RentalUtils for address;
68: 
69:     /////////////////////////////////////////////////////////////////////////////////
70:     //                         Kernel Module Configuration                         //
71:     /////////////////////////////////////////////////////////////////////////////////
72: 
73:     /**
74:      * @dev Instantiate this contract as a module. When using a proxy, the kernel address
75:      *      should be set to address(0).
76:      *
77:      * @param kernel_ Address of the kernel contract.
78:      */
79:     constructor(Kernel kernel_) Module(kernel_) {}
80: 
81:     /**
82:      * @notice Instantiates this contract as a module via a proxy.
83:      *
84:      * @param kernel_ Address of the kernel contract.
85:      */
86:     function MODULE_PROXY_INSTANTIATION(
87:         Kernel kernel_
88:     ) external onlyByProxy onlyUninitialized {
89:         kernel = kernel_;
90:         initialized = true;
91:     }
92: 
93:     /**
94:      * @notice Specifies which version of a module is being implemented.
95:      */
96:     function VERSION() external pure override returns (uint8 major, uint8 minor) {
97:         return (1, 0);
98:     }
99: 
100:     /**
101:      * @notice Defines the keycode for this module.
102:      */
103:     function KEYCODE() public pure override returns (Keycode) {
104:         return Keycode.wrap("STORE");
105:     }
106: 
107:     /////////////////////////////////////////////////////////////////////////////////
108:     //                              View Functions                                 //
109:     /////////////////////////////////////////////////////////////////////////////////
110: 
111:     /**
112:      * @notice Determines if an asset is actively being rented by a wallet.
113:      *
114:      * @param recipient  Address of the wallet which rents the asset.
115:      * @param token      Address of the token.
116:      * @param identifier ID of the token.
117:      */
118:     function isRentedOut(
119:         address recipient,
120:         address token,
121:         uint256 identifier
122:     ) external view returns (bool) {
123:         // calculate the rental ID
124:         RentalId rentalId = RentalUtils.getItemPointer(recipient, token, identifier);
125: 
126:         // Determine if there is a positive amount
127:         return rentedAssets[rentalId] != 0;
128:     }
129: 
130:     /**
131:      * @notice Fetches the hook address that is pointing at the the target.
132:      *
133:      * @param to Address which has a hook pointing to it.
134:      */
135:     function contractToHook(address to) external view returns (address) {
136:         // Fetch the hook that the address currently points to.
137:         address hook = _contractToHook[to];
138: 
139:         // This hook may have been disabled without setting a new hook to take its place.
140:         // So if the hook is disabled, then return the 0 address.
141:         return hookStatus[hook] != 0 ? hook : address(0);
142:     }
143: 
144:     /**
145:      * @notice Determines whether the `onTransaction()` function is enabled for the hook.
146:      *
147:      * @param hook Address of the hook contract.
148:      */
149:     function hookOnTransaction(address hook) external view returns (bool) {
150:         // 1 is 0x00000001. Determines if the masked bit is enabled.
151:         return (uint8(1) & hookStatus[hook]) != 0;
152:     }
153: 
154:     /**
155:      * @notice Determines whether the `onStart()` function is enabled for the hook.
156:      *
157:      * @param hook Address of the hook contract.
158:      */
159:     function hookOnStart(address hook) external view returns (bool) {
160:         // 2 is 0x00000010. Determines if the masked bit is enabled.
161:         return uint8(2) & hookStatus[hook] != 0;
162:     }
163: 
164:     /**
165:      * @notice Determines whether the `onStop()` function is enabled for the hook.
166:      *
167:      * @param hook Address of the hook contract.
168:      */
169:     function hookOnStop(address hook) external view returns (bool) {
170:         // 4 is 0x00000100. Determines if the masked bit is enabled.
171:         return uint8(4) & hookStatus[hook] != 0;
172:     }
173: 
174:     /////////////////////////////////////////////////////////////////////////////////
175:     //                            External Functions                               //
176:     /////////////////////////////////////////////////////////////////////////////////
177: 
178:     /**
179:      * @notice Adds an order hash to storage. Once an order hash is added to storage,
180:      *         the assets contained within are considered actively rented. Additionally,
181:      *         rental asset IDs are added to storage which creates a blocklist on those
182:      *         assets. When the blocklist is active, the protocol guard becomes active on
183:      *         them and prevents transfer or approval of the assets by the owner of the
184:      *         safe.
185:      *
186:      * @param orderHash          Hash of the rental order which is added to storage.
187:      * @param rentalAssetUpdates Asset update structs which are added to storage.
188:      */
189:     function addRentals(
190:         bytes32 orderHash,
191:         RentalAssetUpdate[] memory rentalAssetUpdates
192:     ) external onlyByProxy permissioned {
193:         // Add the order to storage.
194:         orders[orderHash] = true;
195: 
196:         // Add the rented items to storage.
197:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {
198:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
199: 
200:             // Update the order hash for that item.
201:             rentedAssets[asset.rentalId] += asset.amount;
202:         }
203:     }
204: 
205:     /**
206:      * @notice Removes an order hash from storage. Once an order hash is removed from
207:      *         storage, it can no longer be stopped since the protocol will have no
208:      *         record of the order. Addtionally, rental asset IDs are removed from
209:      *         storage. Once these hashes are removed, they are no longer blocklisted
210:      *         from being transferred out of the rental wallet by the owner.
211:      *
212:      * @param orderHash          Hash of the rental order which will be removed from
213:      *                           storage.
214:      * @param rentalAssetUpdates Asset update structs which will be removed from storage.
215:      */
216:     function removeRentals(
217:         bytes32 orderHash,
218:         RentalAssetUpdate[] calldata rentalAssetUpdates
219:     ) external onlyByProxy permissioned {
220:         // The order must exist to be deleted.
221:         if (!orders[orderHash]) {
222:             revert Errors.StorageModule_OrderDoesNotExist(orderHash);
223:         } else {
224:             // Delete the order from storage.
225:             delete orders[orderHash];
226:         }
227: 
228:         // Process each rental asset.
229:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {
230:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
231: 
232:             // Reduce the amount of tokens for the particular rental ID.
233:             rentedAssets[asset.rentalId] -= asset.amount;
234:         }
235:     }
236: 
237:     /**
238:      * @notice Behaves the same as `removeRentals()`, except that orders are processed in
239:      *          a loop.
240:      *
241:      * @param orderHashes        All order hashes which will be removed from storage.
242:      * @param rentalAssetUpdates Asset update structs which will be removed from storage.
243:      */
244:     function removeRentalsBatch(
245:         bytes32[] calldata orderHashes,
246:         RentalAssetUpdate[] calldata rentalAssetUpdates
247:     ) external onlyByProxy permissioned {
248:         // Delete the orders from storage.
249:         for (uint256 i = 0; i < orderHashes.length; ++i) {
250:             // The order must exist to be deleted.
251:             if (!orders[orderHashes[i]]) {
252:                 revert Errors.StorageModule_OrderDoesNotExist(orderHashes[i]);
253:             } else {
254:                 // Delete the order from storage.
255:                 delete orders[orderHashes[i]];
256:             }
257:         }
258: 
259:         // Process each rental asset.
260:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {
261:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
262: 
263:             // Reduce the amount of tokens for the particular rental ID.
264:             rentedAssets[asset.rentalId] -= asset.amount;
265:         }
266:     }
267: 
268:     /**
269:      * @notice Adds the addresss of a rental safe to storage so that protocol-deployed
270:      *         rental safes can be distinguished from those deployed elsewhere.
271:      *
272:      * @param safe Address of the rental safe to add to storage.
273:      */
274:     function addRentalSafe(address safe) external onlyByProxy permissioned {
275:         // Get the new safe count.
276:         uint256 newSafeCount = totalSafes + 1;
277: 
278:         // Register the safe as deployed.
279:         deployedSafes[safe] = newSafeCount;
280: 
281:         // Increment nonce.
282:         totalSafes = newSafeCount;
283:     }
284: 
285:     /**
286:      * @notice Connects a hook to a destination address. Once an active path is made,
287:      *         any transactions originating from a rental safe to the target address
288:      *         will use a hook as middleware. The hook chosen is determined by the path
289:      *         set.
290:      *
291:      * @param to   Target address which will use a hook as middleware.
292:      * @param hook Address of the hook which will act as a middleware.
293:      */
294:     function updateHookPath(address to, address hook) external onlyByProxy permissioned {
295:         // Require that the `to` address is a contract.
296:         if (to.code.length == 0) revert Errors.StorageModule_NotContract(to);
297: 
298:         // Require that the `hook` address is a contract.
299:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook);
300: 
301:         // Point the `to` address to the `hook` address.
302:         _contractToHook[to] = hook;
303:     }
304: 
305:     /**
306:      * @notice Updates a hook with a bitmap that indicates its active functionality.
307:      *         A valid bitmap is any decimal value that is less than or equal
308:      *         to 7 (0x111).
309:      *
310:      * @param hook   Address of the hook contract.
311:      * @param bitmap Decimal value that defines the active functionality on the hook.
312:      */
313:     function updateHookStatus(
314:         address hook,
315:         uint8 bitmap
316:     ) external onlyByProxy permissioned {
317:         // Require that the `hook` address is a contract.
318:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook);
319: 
320:         // 7 is 0x00000111. This ensures that only a valid bitmap can be set.
321:         if (bitmap > uint8(7))
322:             revert Errors.StorageModule_InvalidHookStatusBitmap(bitmap);
323: 
324:         // Update the status of the hook.
325:         hookStatus[hook] = bitmap;
326:     }
327: 
328:     /**
329:      * @notice Toggles whether an address can be delegate called.
330:      *
331:      * @param delegate  Address which can be delegate called.
332:      * @param isEnabled Boolean indicating whether the address is enabled.
333:      */
334:     function toggleWhitelistDelegate(
335:         address delegate,
336:         bool isEnabled
337:     ) external onlyByProxy permissioned {
338:         whitelistedDelegates[delegate] = isEnabled;
339:     }
340: 
341:     /**
342:      * @notice Toggles whether an extension is whitelisted.
343:      *
344:      * @param extension Gnosis safe module which can be added to a rental safe.
345:      * @param isEnabled Boolean indicatingwhether the module is enabled.
346:      */
347:     function toggleWhitelistExtension(
348:         address extension,
349:         bool isEnabled
350:     ) external onlyByProxy permissioned {
351:         whitelistedExtensions[extension] = isEnabled;
352:     }
353: 
354:     /**
355:      * @notice Upgrades the contract to a different implementation. This implementation
356:      *         contract must be compatible with ERC-1822 or else the upgrade will fail.
357:      *
358:      * @param newImplementation Address of the implementation contract to upgrade to.
359:      */
360:     function upgrade(address newImplementation) external onlyByProxy permissioned {
361:         // _upgrade is implemented in the Proxiable contract.
362:         _upgrade(newImplementation);
363:     }
364: 
365:     /**
366:      * @notice Freezes the contract which prevents upgrading the implementation contract.
367:      *         There is no way to unfreeze once a contract has been frozen.
368:      */
369:     function freeze() external onlyByProxy permissioned {
370:         // _freeze is implemented in the Proxiable contract.
371:         _freeze();
372:     }
373: }
374: 

```


*GitHub* : [1](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L1-L1)

```solidity
1: // SPDX-License-Identifier: BUSL-1.1
2: pragma solidity ^0.8.20;
3: 
4: import {RentalId, RentalAssetUpdate} from "@src/libraries/RentalStructs.sol";
5: 
6: /**
7:  * @title Accumulator
8:  * @notice Package that implements functionality for managing dynamically allocated data
9:  *         struct arrays directly in memory. The rationale for this was the need for an
10:  *         array of structs where the total size is not known at instantiation.
11:  */
12: abstract contract Accumulator {
13:     /**
14:      * @dev Accumulates an intermediary representation of a dynamic array of
15:      *      `RentalAssetUpdate` structs.
16:      *
17:      * In memory, the format of `rentalAssets` will be as follows:
18:      *
19:      * 0x00: Length of the intermediary representation bytes data
20:      * 0x20: Number of `RentalAssetUpdate` elements stored
21:      * 0x40: `rentalId` of the first element
22:      * 0x60: `amount` of the first element
23:      * 0x80: `rentalId` of the second element
24:      * 0xa0: `amount` of the second element
25:      * 0xc0: ...
26:      *
27:      * @param rentalAssets      Bytes value which will accumulate `RentalAssetUpdate`
28:      *                          structs.
29:      * @param rentalId          Rental ID to include in the next `RentalAssetUpdate`.
30:      * @param rentalAssetAmount Amount to include in the next `RentalAssetUpdate`.
31:      */
32:     function _insert(
33:         bytes memory rentalAssets,
34:         RentalId rentalId,
35:         uint256 rentalAssetAmount
36:     ) internal pure {
37:         // Place the rental ID on the stack.
38:         bytes32 _rentalId = RentalId.unwrap(rentalId);
39: 
40:         assembly {
41:             // This is the first time inserting into this bytes data.
42:             if eq(mload(rentalAssets), 0) {
43:                 // Create some space for the initial element length word.
44:                 mstore(rentalAssets, 0x20)
45: 
46:                 // Zero out the number of elements.
47:                 mstore(add(0x20, rentalAssets), 0x00)
48:             }
49: 
50:             // Calculate the new size of the bytes data by adding
51:             // the size of a `RentalAssetUpdate` struct.
52:             let newByteDataSize := add(mload(rentalAssets), 0x40)
53: 
54:             // Get the pointer for where the element data begins.
55:             let rentalAssetElementPtr := add(rentalAssets, 0x20)
56: 
57:             // Increase the number of rental elements by one.
58:             let elements := add(mload(rentalAssetElementPtr), 1)
59: 
60:             // Calculate the position for the new rental ID.
61:             // To do this, calculate the total length of the element portion, then
62:             // subtract by the initial offset. In this case, the offset is the 32-byte
63:             // word (0x20) which contains the length of the array.
64:             let newItemPosition := add(
65:                 rentalAssetElementPtr,
66:                 sub(mul(elements, 0x40), 0x20)
67:             )
68: 
69:             // Store the new byte data size
70:             mstore(rentalAssets, newByteDataSize)
71: 
72:             // Store the new number of elements
73:             mstore(rentalAssetElementPtr, elements)
74: 
75:             // Store the rental ID
76:             mstore(newItemPosition, _rentalId)
77: 
78:             // Store the amount in the adjacent 32-byte word
79:             mstore(add(newItemPosition, 0x20), rentalAssetAmount)
80: 
81:             // Update the free memory pointer so that memory is safe
82:             // once we stop doing dynamic memory array inserts
83:             mstore(0x40, add(newItemPosition, 0x40))
84:         }
85:     }
86: 
87:     /**
88:      * @dev Converts an intermediary dynamic array of `RentalAssetUpdate` into a
89:      *      conventional Solidity array.
90:      *
91:      * @param rentalAssetUpdates Bytes data that represents an array of
92:      *                           `RentalAssetUpdate` structs.
93:      *
94:      * @return updates Solidity representation of a `RentalAssetUpdate` array.
95:      */
96:     function _convertToStatic(
97:         bytes memory rentalAssetUpdates
98:     ) internal pure returns (RentalAssetUpdate[] memory updates) {
99:         // Pointer to the rental asset update data.
100:         bytes32 rentalAssetUpdatePointer;
101: 
102:         // Load the length of the rental asset update items.
103:         uint256 rentalAssetUpdateLength;
104:         assembly {
105:             // Get a pointer to the number of elements in the bytes data.
106:             // With the 0x20 offset, we would be loading the length of the entire
107:             // byte string, but we want the element length which starts one
108:             // word to the right.
109:             rentalAssetUpdatePointer := add(0x20, rentalAssetUpdates)
110: 
111:             // Load the number of elements.
112:             rentalAssetUpdateLength := mload(rentalAssetUpdatePointer)
113:         }
114: 
115:         // Instantiate the update array.
116:         updates = new RentalAssetUpdate[](rentalAssetUpdateLength);
117: 
118:         // Iterate through each item in the byte data, and add it as
119:         // an entry to the array.
120:         for (uint256 i = 0; i < rentalAssetUpdateLength; ++i) {
121:             // Define the placeholders.
122:             RentalId rentalId;
123:             uint256 amount;
124: 
125:             // Extract the current element from the byte data.
126:             assembly {
127:                 // Determine element offset by multiplying the length of a
128:                 // RentalAssetUpdate struct (0x40) by the current index, then
129:                 // add a word to make sure the next word is accessed because the
130:                 // offset defaults to being set to the length pointer.
131:                 let currentElementOffset := add(0x20, mul(i, 0x40))
132: 
133:                 // Load the rental ID starting at the data pointer.
134:                 rentalId := mload(add(rentalAssetUpdatePointer, currentElementOffset))
135: 
136:                 // Load the amount at the data pointer adjacent to it.
137:                 amount := mload(
138:                     add(0x20, add(rentalAssetUpdatePointer, currentElementOffset))
139:                 )
140:             }
141: 
142:             // Set the items
143:             updates[i] = RentalAssetUpdate(rentalId, amount);
144:         }
145:     }
146: }
147: 

```


*GitHub* : [1](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L1-L1)

```solidity
1: // SPDX-License-Identifier: BUSL-1.1
2: pragma solidity ^0.8.20;
3: 
4: import {ZoneParameters} from "@seaport-core/lib/rental/ConsiderationStructs.sol";
5: import {ReceivedItem, SpentItem} from "@seaport-types/lib/ConsiderationStructs.sol";
6: import {LibString} from "@solady/utils/LibString.sol";
7: 
8: import {ISafe} from "@src/interfaces/ISafe.sol";
9: import {IHook} from "@src/interfaces/IHook.sol";
10: import {ZoneInterface} from "@src/interfaces/IZone.sol";
11: 
12: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol";
13: import {toKeycode, toRole} from "@src/libraries/KernelUtils.sol";
14: import {RentalUtils} from "@src/libraries/RentalUtils.sol";
15: import {Signer} from "@src/packages/Signer.sol";
16: import {Zone} from "@src/packages/Zone.sol";
17: import {Accumulator} from "@src/packages/Accumulator.sol";
18: import {Storage} from "@src/modules/Storage.sol";
19: import {PaymentEscrow} from "@src/modules/PaymentEscrow.sol";
20: import {
21:     RentalOrder,
22:     RentPayload,
23:     SeaportPayload,
24:     Hook,
25:     OrderFulfillment,
26:     OrderMetadata,
27:     OrderType,
28:     Item,
29:     ItemType,
30:     SettleTo,
31:     RentalId,
32:     RentalAssetUpdate
33: } from "@src/libraries/RentalStructs.sol";
34: import {Errors} from "@src/libraries/Errors.sol";
35: import {Events} from "@src/libraries/Events.sol";
36: 
37: /**
38:  * @title Create
39:  * @notice Acts as an interface for all behavior related to creating a rental.
40:  */
41: contract Create is Policy, Signer, Zone, Accumulator {
42:     using RentalUtils for Item;
43:     using RentalUtils for Item[];
44:     using RentalUtils for SpentItem;
45:     using RentalUtils for ReceivedItem;
46:     using RentalUtils for OrderType;
47: 
48:     /////////////////////////////////////////////////////////////////////////////////
49:     //                         Kernel Policy Configuration                         //
50:     /////////////////////////////////////////////////////////////////////////////////
51: 
52:     // Modules that the policy depends on.
53:     Storage public STORE;
54:     PaymentEscrow public ESCRW;
55: 
56:     /**
57:      * @dev Instantiate this contract as a policy.
58:      *
59:      * @param kernel_ Address of the kernel contract.
60:      */
61:     constructor(Kernel kernel_) Policy(kernel_) Signer() Zone() {}
62: 
63:     /**
64:      * @notice Upon policy activation, configures the modules that the policy depends on.
65:      *         If a module is ever upgraded that this policy depends on, the kernel will
66:      *         call this function again to ensure this policy has the current address
67:      *         of the module.
68:      *
69:      * @return dependencies Array of keycodes which represent modules that
70:      *                      this policy depends on.
71:      */
72:     function configureDependencies()
73:         external
74:         override
75:         onlyKernel
76:         returns (Keycode[] memory dependencies)
77:     {
78:         dependencies = new Keycode[](2);
79: 
80:         dependencies[0] = toKeycode("STORE");
81:         STORE = Storage(getModuleAddress(toKeycode("STORE")));
82: 
83:         dependencies[1] = toKeycode("ESCRW");
84:         ESCRW = PaymentEscrow(getModuleAddress(toKeycode("ESCRW")));
85:     }
86: 
87:     /**
88:      * @notice Upon policy activation, permissions are requested from the kernel to access
89:      *         particular keycode <> function selector pairs. Once these permissions are
90:      *         granted, they do not change and can only be revoked when the policy is
91:      *         deactivated by the kernel.
92:      *
93:      * @return requests Array of keycode <> function selector pairs which represent
94:      *                  permissions for the policy.
95:      */
96:     function requestPermissions()
97:         external
98:         view
99:         override
100:         onlyKernel
101:         returns (Permissions[] memory requests)
102:     {
103:         requests = new Permissions[](2);
104:         requests[0] = Permissions(toKeycode("STORE"), STORE.addRentals.selector);
105:         requests[1] = Permissions(toKeycode("ESCRW"), ESCRW.increaseDeposit.selector);
106:     }
107: 
108:     /////////////////////////////////////////////////////////////////////////////////
109:     //                              View Functions                                 //
110:     /////////////////////////////////////////////////////////////////////////////////
111: 
112:     /**
113:      * @notice Retrieves the domain separator.
114:      *
115:      * @return The domain separator for the protocol.
116:      */
117:     function domainSeparator() external view returns (bytes32) {
118:         return _DOMAIN_SEPARATOR;
119:     }
120: 
121:     /**
122:      * @notice Derives the rental order EIP-712 compliant hash from a `RentalOrder`.
123:      *
124:      * @param order Rental order converted to a hash.
125:      */
126:     function getRentalOrderHash(
127:         RentalOrder memory order
128:     ) external view returns (bytes32) {
129:         return _deriveRentalOrderHash(order);
130:     }
131: 
132:     /**
133:      * @notice Derives the rent payload EIP-712 compliant hash from a `RentPayload`.
134:      *
135:      * @param payload Rent payload converted to a hash.
136:      */
137:     function getRentPayloadHash(
138:         RentPayload memory payload
139:     ) external view returns (bytes32) {
140:         return _deriveRentPayloadHash(payload);
141:     }
142: 
143:     /**
144:      * @notice Derives the order metadata EIP-712 compliant hash from an `OrderMetadata`.
145:      *
146:      * @param metadata Order metadata converted to a hash.
147:      */
148:     function getOrderMetadataHash(
149:         OrderMetadata memory metadata
150:     ) external view returns (bytes32) {
151:         return _deriveOrderMetadataHash(metadata);
152:     }
153: 
154:     /////////////////////////////////////////////////////////////////////////////////
155:     //                            Internal Functions                               //
156:     /////////////////////////////////////////////////////////////////////////////////
157: 
158:     /**
159:      * @dev Helper function to emit an event which signals a rental order has started.
160:      *
161:      * @param order     Rental order to emit.
162:      * @param orderHash Order hash of the seaport order.
163:      * @param extraData Any extra data to be emitted which was supplied by the offerer.
164:      */
165:     function _emitRentalOrderStarted(
166:         RentalOrder memory order,
167:         bytes32 orderHash,
168:         bytes memory extraData
169:     ) internal {
170:         // Emit the event.
171:         emit Events.RentalOrderStarted(
172:             orderHash,
173:             extraData,
174:             order.seaportOrderHash,
175:             order.items,
176:             order.hooks,
177:             order.orderType,
178:             order.lender,
179:             order.renter,
180:             order.rentalWallet,
181:             order.startTimestamp,
182:             order.endTimestamp
183:         );
184:     }
185: 
186:     /**
187:      * @dev Processes the offer items for inclusion in a BASE order. All offer items must
188:      *      adhere to the BASE order format, else execution will revert.
189:      *
190:      * @param rentalItems Running array of items that comprise the rental order.
191:      * @param offers      Array of offer items to include in the the order.
192:      * @param startIndex  Index to begin adding the offer items to the
193:      *                    `rentalItems` array.
194:      */
195:     function _processBaseOrderOffer(
196:         Item[] memory rentalItems,
197:         SpentItem[] memory offers,
198:         uint256 startIndex
199:     ) internal pure {
200:         // Must be at least one offer item.
201:         if (offers.length == 0) {
202:             revert Errors.CreatePolicy_OfferCountZero();
203:         }
204: 
205:         // Define elements of the item which depend on the token type.
206:         ItemType itemType;
207: 
208:         // Process each offer item.
209:         for (uint256 i; i < offers.length; ++i) {
210:             // Get the offer item.
211:             SpentItem memory offer = offers[i];
212: 
213:             // Handle the ERC721 item.
214:             if (offer.isERC721()) {
215:                 itemType = ItemType.ERC721;
216:             }
217:             // Handle the ERC1155 item.
218:             else if (offer.isERC1155()) {
219:                 itemType = ItemType.ERC1155;
220:             }
221:             // ERC20s are not supported as offer items in a BASE order.
222:             else {
223:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(offer.itemType);
224:             }
225: 
226:             // An ERC721 or ERC1155 offer item is considered a rented asset which will be
227:             // returned to the lender upon expiration of the rental order.
228:             rentalItems[i + startIndex] = Item({
229:                 itemType: itemType,
230:                 settleTo: SettleTo.LENDER,
231:                 token: offer.token,
232:                 amount: offer.amount,
233:                 identifier: offer.identifier
234:             });
235:         }
236:     }
237: 
238:     /**
239:      * @dev Processes the offer items for inclusion in a PAY order. All offer items must
240:      *      adhere to the PAY order format, else execution will revert.
241:      *
242:      * @param rentalItems Running array of items that comprise the rental order.
243:      * @param offers      Array of offer items to include in the the order.
244:      * @param startIndex  Index to begin adding the offer items to the
245:      *                    `rentalItems` array.
246:      */
247:     function _processPayOrderOffer(
248:         Item[] memory rentalItems,
249:         SpentItem[] memory offers,
250:         uint256 startIndex
251:     ) internal pure {
252:         // Keep track of each item type.
253:         uint256 totalRentals;
254:         uint256 totalPayments;
255: 
256:         // Define elements of the item which depend on the token type.
257:         ItemType itemType;
258:         SettleTo settleTo;
259: 
260:         // Process each offer item.
261:         for (uint256 i; i < offers.length; ++i) {
262:             // Get the offer item.
263:             SpentItem memory offer = offers[i];
264: 
265:             // Handle the ERC721 item.
266:             if (offer.isERC721()) {
267:                 // The ERC721 will be returned to the lender upon expiration
268:                 // of the rental order.
269:                 itemType = ItemType.ERC721;
270:                 settleTo = SettleTo.LENDER;
271: 
272:                 // Increment rentals.
273:                 totalRentals++;
274:             }
275:             // Handle the ERC1155 item.
276:             else if (offer.isERC1155()) {
277:                 // The ERC1155 will be returned to the lender upon expiration
278:                 // of the rental order.
279:                 itemType = ItemType.ERC1155;
280:                 settleTo = SettleTo.LENDER;
281: 
282:                 // Increment rentals.
283:                 totalRentals++;
284:             }
285:             // Process an ERC20 offer item.
286:             else if (offer.isERC20()) {
287:                 // An ERC20 offer item is considered a payment to the renter upon
288:                 // expiration of the rental order.
289:                 itemType = ItemType.ERC20;
290:                 settleTo = SettleTo.RENTER;
291: 
292:                 // Increment payments.
293:                 totalPayments++;
294:             }
295:             // Revert if unsupported item type.
296:             else {
297:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(offer.itemType);
298:             }
299: 
300:             // Create the item.
301:             rentalItems[i + startIndex] = Item({
302:                 itemType: itemType,
303:                 settleTo: settleTo,
304:                 token: offer.token,
305:                 amount: offer.amount,
306:                 identifier: offer.identifier
307:             });
308:         }
309: 
310:         // PAY order offer must have at least one rental and one payment.
311:         if (totalRentals == 0 || totalPayments == 0) {
312:             revert Errors.CreatePolicy_ItemCountZero(totalRentals, totalPayments);
313:         }
314:     }
315: 
316:     /**
317:      * @dev Processes the consideration items for inclusion in a BASE order. All
318:      *      consideration items must adhere to the BASE order format, else
319:      *      execution will revert.
320:      *
321:      * @param rentalItems    Running array of items that comprise the rental order.
322:      * @param considerations Array of consideration items to include in the the order.
323:      * @param startIndex     Index to begin adding the offer items to the
324:      *                       `rentalItems` array.
325:      */
326:     function _processBaseOrderConsideration(
327:         Item[] memory rentalItems,
328:         ReceivedItem[] memory considerations,
329:         uint256 startIndex
330:     ) internal pure {
331:         // Must be at least one consideration item.
332:         if (considerations.length == 0) {
333:             revert Errors.CreatePolicy_ConsiderationCountZero();
334:         }
335: 
336:         // Process each consideration item.
337:         for (uint256 i; i < considerations.length; ++i) {
338:             // Get the consideration item.
339:             ReceivedItem memory consideration = considerations[i];
340: 
341:             // Only process an ERC20 item.
342:             if (!consideration.isERC20()) {
343:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
344:                     consideration.itemType
345:                 );
346:             }
347: 
348:             // An ERC20 consideration item is considered a payment to the lender upon
349:             // expiration of the rental order.
350:             rentalItems[i + startIndex] = Item({
351:                 itemType: ItemType.ERC20,
352:                 settleTo: SettleTo.LENDER,
353:                 token: consideration.token,
354:                 amount: consideration.amount,
355:                 identifier: consideration.identifier
356:             });
357:         }
358:     }
359: 
360:     /**
361:      * @dev Processes the consideration items for inclusion in a PAYEE order. All
362:      *      consideration items must adhere to the PAYEE order format, else
363:      *      execution will revert.
364:      *
365:      * @param considerations Array of consideration items to include in the the order.
366:      */
367:     function _processPayeeOrderConsideration(
368:         ReceivedItem[] memory considerations
369:     ) internal pure {
370:         // Keep track of each item type.
371:         uint256 totalRentals;
372:         uint256 totalPayments;
373: 
374:         // Process each consideration item.
375:         for (uint256 i; i < considerations.length; ++i) {
376:             // Get the consideration item.
377:             ReceivedItem memory consideration = considerations[i];
378: 
379:             // Process an ERC20 item.
380:             if (consideration.isERC20()) {
381:                 totalPayments++;
382:             }
383:             // Process an ERC721 or ERC1155 consideration item.
384:             else if (consideration.isRental()) {
385:                 totalRentals++;
386:             }
387:             // Revert if unsupported item type.
388:             else {
389:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
390:                     consideration.itemType
391:                 );
392:             }
393:         }
394: 
395:         // PAYEE order consideration must have at least one rental and one payment.
396:         if (totalRentals == 0 || totalPayments == 0) {
397:             revert Errors.CreatePolicy_ItemCountZero(totalRentals, totalPayments);
398:         }
399:     }
400: 
401:     /**
402:      * @dev Converts an offer array and a consideration array into a single array of
403:      *      `Item` which comprise a rental order. The offers and considerations must
404:      *      adhere to a specific set of rules depending on the type of order being
405:      *      constructed.
406:      *
407:      * @param offers         Array of Seaport offer items.
408:      * @param considerations Array of seaport consideration items.
409:      * @param orderType      Order type of the rental.
410:      */
411:     function _convertToItems(
412:         SpentItem[] memory offers,
413:         ReceivedItem[] memory considerations,
414:         OrderType orderType
415:     ) internal pure returns (Item[] memory items) {
416:         // Initialize an array of items.
417:         items = new Item[](offers.length + considerations.length);
418: 
419:         // Process items for a base order.
420:         if (orderType.isBaseOrder()) {
421:             // Process offer items.
422:             _processBaseOrderOffer(items, offers, 0);
423: 
424:             // Process consideration items.
425:             _processBaseOrderConsideration(items, considerations, offers.length);
426:         }
427:         // Process items for a pay order.
428:         else if (orderType.isPayOrder()) {
429:             // Process offer items.
430:             _processPayOrderOffer(items, offers, 0);
431: 
432:             // Assert that no consideration items are provided.
433:             if (considerations.length > 0) {
434:                 revert Errors.CreatePolicy_ConsiderationCountNonZero(
435:                     considerations.length
436:                 );
437:             }
438:         }
439:         // Process items for a payee order.
440:         else if (orderType.isPayeeOrder()) {
441:             // Assert that no offer items are provided.
442:             if (offers.length > 0) {
443:                 revert Errors.CreatePolicy_OfferCountNonZero(offers.length);
444:             }
445: 
446:             // Process consideration items.
447:             _processPayeeOrderConsideration(considerations);
448:         }
449:         // Revert if order type is not supported.
450:         else {
451:             revert Errors.Shared_OrderTypeNotSupported(uint8(orderType));
452:         }
453:     }
454: 
455:     /**
456:      * @dev When a rental order is created, process each hook one by one but only if
457:      *      the hook's status is set to execute on a rental start.
458:      *
459:      * @param hooks        Array of hooks to process for the order.
460:      * @param offerItems   Array of offer items which are referenced by the hooks
461:      * @param rentalWallet Address of the rental wallet which is the recipient
462:      *                     of the rented assets.
463:      */
464:     function _addHooks(
465:         Hook[] memory hooks,
466:         SpentItem[] memory offerItems,
467:         address rentalWallet
468:     ) internal {
469:         // Define hook target, offer item index, and an offer item.
470:         address target;
471:         uint256 itemIndex;
472:         SpentItem memory offer;
473: 
474:         // Loop through each hook in the payload.
475:         for (uint256 i = 0; i < hooks.length; ++i) {
476:             // Get the hook's target address.
477:             target = hooks[i].target;
478: 
479:             // Check that the hook is reNFT-approved to execute on rental start.
480:             if (!STORE.hookOnStart(target)) {
481:                 revert Errors.Shared_DisabledHook(target);
482:             }
483: 
484:             // Get the offer item index for this hook.
485:             itemIndex = hooks[i].itemIndex;
486: 
487:             // Get the offer item for this hook.
488:             offer = offerItems[itemIndex];
489: 
490:             // Make sure the offer item is an ERC721 or ERC1155.
491:             if (!offer.isRental()) {
492:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
493:             }
494: 
495:             // Call the hook with data about the rented item.
496:             try
497:                 IHook(target).onStart(
498:                     rentalWallet,
499:                     offer.token,
500:                     offer.identifier,
501:                     offer.amount,
502:                     hooks[i].extraData
503:                 )
504:             {} catch Error(string memory revertReason) {
505:                 // Revert with reason given.
506:                 revert Errors.Shared_HookFailString(revertReason);
507:             } catch Panic(uint256 errorCode) {
508:                 // Convert solidity panic code to string.
509:                 string memory stringErrorCode = LibString.toString(errorCode);
510: 
511:                 // Revert with panic code.
512:                 revert Errors.Shared_HookFailString(
513:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
514:                 );
515:             } catch (bytes memory revertData) {
516:                 // Fallback to an error that returns the byte data.
517:                 revert Errors.Shared_HookFailBytes(revertData);
518:             }
519:         }
520:     }
521: 
522:     /**
523:      * @dev Initiates a rental order using a rental payload received by the fulfiller,
524:      *      and a payload from seaport with data involving the assets that were
525:      *      transferred in the order.
526:      *
527:      * @param payload Payload from the order fulfiller.
528:      * @param seaportPayload Payload containing the result of a seaport order fulfillment.
529:      */
530:     function _rentFromZone(
531:         RentPayload memory payload,
532:         SeaportPayload memory seaportPayload
533:     ) internal {
534:         // Check: make sure order metadata is valid with the given seaport order zone hash.
535:         _isValidOrderMetadata(payload.metadata, seaportPayload.zoneHash);
536: 
537:         // Check: verify the fulfiller of the order is an owner of the recipient safe.
538:         _isValidSafeOwner(seaportPayload.fulfiller, payload.fulfillment.recipient);
539: 
540:         // Check: verify each execution was sent to the expected destination.
541:         _executionInvariantChecks(
542:             seaportPayload.totalExecutions,
543:             payload.fulfillment.recipient
544:         );
545: 
546:         // Check: validate and process seaport offer and consideration items based
547:         // on the order type.
548:         Item[] memory items = _convertToItems(
549:             seaportPayload.offer,
550:             seaportPayload.consideration,
551:             payload.metadata.orderType
552:         );
553: 
554:         // PAYEE orders are considered mirror-images of a PAY order. So, PAYEE orders
555:         // do not need to be processed in the same way that other order types do.
556:         if (
557:             payload.metadata.orderType.isBaseOrder() ||
558:             payload.metadata.orderType.isPayOrder()
559:         ) {
560:             // Create an accumulator which will hold all of the rental asset updates, consisting of IDs and
561:             // the rented amount. From this point on, new memory cannot be safely allocated until the
562:             // accumulator no longer needs to include elements.
563:             bytes memory rentalAssetUpdates = new bytes(0);
564: 
565:             // Check if each item is a rental. If so, then generate the rental asset update.
566:             // Memory will become safe again after this block.
567:             for (uint256 i; i < items.length; ++i) {
568:                 if (items[i].isRental()) {
569:                     // Insert the rental asset update into the dynamic array.
570:                     _insert(
571:                         rentalAssetUpdates,
572:                         items[i].toRentalId(payload.fulfillment.recipient),
573:                         items[i].amount
574:                     );
575:                 }
576:             }
577: 
578:             // Generate the rental order.
579:             RentalOrder memory order = RentalOrder({
580:                 seaportOrderHash: seaportPayload.orderHash,
581:                 items: items,
582:                 hooks: payload.metadata.hooks,
583:                 orderType: payload.metadata.orderType,
584:                 lender: seaportPayload.offerer,
585:                 renter: payload.intendedFulfiller,
586:                 rentalWallet: payload.fulfillment.recipient,
587:                 startTimestamp: block.timestamp,
588:                 endTimestamp: block.timestamp + payload.metadata.rentDuration
589:             });
590: 
591:             // Compute the order hash.
592:             bytes32 orderHash = _deriveRentalOrderHash(order);
593: 
594:             // Interaction: Update storage only if the order is a Base Order or Pay order.
595:             STORE.addRentals(orderHash, _convertToStatic(rentalAssetUpdates));
596: 
597:             // Interaction: Increase the deposit value on the payment escrow so
598:             // it knows how many tokens were sent to it.
599:             for (uint256 i = 0; i < items.length; ++i) {
600:                 if (items[i].isERC20()) {
601:                     ESCRW.increaseDeposit(items[i].token, items[i].amount);
602:                 }
603:             }
604: 
605:             // Interaction: Process the hooks associated with this rental.
606:             if (payload.metadata.hooks.length > 0) {
607:                 _addHooks(
608:                     payload.metadata.hooks,
609:                     seaportPayload.offer,
610:                     payload.fulfillment.recipient
611:                 );
612:             }
613: 
614:             // Emit rental order started.
615:             _emitRentalOrderStarted(order, orderHash, payload.metadata.emittedExtraData);
616:         }
617:     }
618: 
619:     /**
620:      * @dev Checks that the order metadata passed with the seaport order is expected.
621:      *
622:      * @param metadata Order metadata that was passed in with the fulfillment.
623:      * @param zoneHash Hash of the order metadata that was passed in when the Seaport
624:      *                 order was signed.
625:      */
626:     function _isValidOrderMetadata(
627:         OrderMetadata memory metadata,
628:         bytes32 zoneHash
629:     ) internal view {
630:         // Check that the rent duration specified is not zero.
631:         if (metadata.rentDuration == 0) {
632:             revert Errors.CreatePolicy_RentDurationZero();
633:         }
634: 
635:         // Check that the zone hash is equal to the derived hash of the metadata.
636:         if (_deriveOrderMetadataHash(metadata) != zoneHash) {
637:             revert Errors.CreatePolicy_InvalidOrderMetadataHash();
638:         }
639:     }
640: 
641:     /**
642:      * @dev Checks that an address is the owner of a protocol-deployed rental safe.
643:      *
644:      * @param owner Address of the potential safe owner.
645:      * @param safe  Address of the potential protocol-deployed rental safe.
646:      */
647:     function _isValidSafeOwner(address owner, address safe) internal view {
648:         // Make sure only protocol-deployed safes can rent.
649:         if (STORE.deployedSafes(safe) == 0) {
650:             revert Errors.CreatePolicy_InvalidRentalSafe(safe);
651:         }
652: 
653:         // Make sure the fulfiller is the owner of the recipient rental safe.
654:         if (!ISafe(safe).isOwner(owner)) {
655:             revert Errors.CreatePolicy_InvalidSafeOwner(owner, safe);
656:         }
657:     }
658: 
659:     /**
660:      * @dev Helper function to check that an execution performed by Seaport resulting
661:      *      in the expected address receiving the asset.
662:      *
663:      * @param execution Execution that was performed by Seaport.
664:      * @param expectedRecipient Address which should now own the rented asset.
665:      */
666:     function _checkExpectedRecipient(
667:         ReceivedItem memory execution,
668:         address expectedRecipient
669:     ) internal pure {
670:         if (execution.recipient != expectedRecipient) {
671:             revert Errors.CreatePolicy_UnexpectedTokenRecipient(
672:                 execution.itemType,
673:                 execution.token,
674:                 execution.identifier,
675:                 execution.amount,
676:                 execution.recipient,
677:                 expectedRecipient
678:             );
679:         }
680:     }
681: 
682:     /**
683:      * @dev After a Seaport order has been executed, invariant checks are made to ensure
684:      *      that all assets are owned by the correct addresses. More specifically, all
685:      *      ERC20 tokens are sent to the payment escrow module, and all rental assets
686:      *      are in the intended recipient's rental safe.
687:      *
688:      * @param executions Each execution that was performed by Seaport.
689:      * @param expectedRentalSafe The intended recipient of the rental assets.
690:      */
691:     function _executionInvariantChecks(
692:         ReceivedItem[] memory executions,
693:         address expectedRentalSafe
694:     ) internal view {
695:         for (uint256 i = 0; i < executions.length; ++i) {
696:             ReceivedItem memory execution = executions[i];
697: 
698:             // ERC20 invariant where the recipient must be the payment escrow.
699:             if (execution.isERC20()) {
700:                 _checkExpectedRecipient(execution, address(ESCRW));
701:             }
702:             // ERC721 and ERC1155 invariants where the recipient must
703:             // be the expected rental safe.
704:             else if (execution.isRental()) {
705:                 _checkExpectedRecipient(execution, expectedRentalSafe);
706:             }
707:             // Revert if unsupported item type.
708:             else {
709:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
710:                     execution.itemType
711:                 );
712:             }
713:         }
714:     }
715: 
716:     /////////////////////////////////////////////////////////////////////////////////
717:     //                            External Functions                               //
718:     /////////////////////////////////////////////////////////////////////////////////
719: 
720:     /**
721:      * @notice Callback function implemented to make this contract a valid Seaport zone.
722:      *         It can be considered the entrypoint to creating a rental. When a seaport
723:      *         order specifies the create policy as its zone address, Seaport will call
724:      *         this function after each order in the batch is processed. A call to
725:      *         `validateOrder` is what kicks off the rental process, and performs steps
726:      *         to convert a seaport order into a rental order which is stored
727:      *         by the protocol.
728:      *
729:      * @param zoneParams Parameters from the seaport order.
730:      *
731:      * @return validOrderMagicValue A `bytes4` value to return back to Seaport.
732:      */
733:     function validateOrder(
734:         ZoneParameters calldata zoneParams
735:     ) external override onlyRole("SEAPORT") returns (bytes4 validOrderMagicValue) {
736:         // Decode the signed rental zone payload from the extra data.
737:         (RentPayload memory payload, bytes memory signature) = abi.decode(
738:             zoneParams.extraData,
739:             (RentPayload, bytes)
740:         );
741: 
742:         // Create a payload of seaport data.
743:         SeaportPayload memory seaportPayload = SeaportPayload({
744:             orderHash: zoneParams.orderHash,
745:             zoneHash: zoneParams.zoneHash,
746:             offer: zoneParams.offer,
747:             consideration: zoneParams.consideration,
748:             totalExecutions: zoneParams.totalExecutions,
749:             fulfiller: zoneParams.fulfiller,
750:             offerer: zoneParams.offerer
751:         });
752: 
753:         // Check: The signature from the protocol signer has not expired.
754:         _validateProtocolSignatureExpiration(payload.expiration);
755: 
756:         // Check: The fulfiller is the intended fulfiller.
757:         _validateFulfiller(payload.intendedFulfiller, seaportPayload.fulfiller);
758: 
759:         // Recover the signer from the payload.
760:         address signer = _recoverSignerFromPayload(
761:             _deriveRentPayloadHash(payload),
762:             signature
763:         );
764: 
765:         // Check: The data matches the signature and that the protocol signer is the one that signed.
766:         if (!kernel.hasRole(signer, toRole("CREATE_SIGNER"))) {
767:             revert Errors.CreatePolicy_UnauthorizedCreatePolicySigner();
768:         }
769: 
770:         // Initiate the rental using the rental manager.
771:         _rentFromZone(payload, seaportPayload);
772: 
773:         // Return the selector of validateOrder as the magic value.
774:         validOrderMagicValue = ZoneInterface.validateOrder.selector;
775:     }
776: }
777: 

```


*GitHub* : [1](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L1-L1)

```solidity
1: // SPDX-License-Identifier: BUSL-1.1
2: pragma solidity ^0.8.20;
3: 
4: import {Enum} from "@safe-contracts/common/Enum.sol";
5: import {LibString} from "@solady/utils/LibString.sol";
6: 
7: import {ISafe} from "@src/interfaces/ISafe.sol";
8: import {IHook} from "@src/interfaces/IHook.sol";
9: 
10: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol";
11: import {toKeycode} from "@src/libraries/KernelUtils.sol";
12: import {RentalUtils} from "@src/libraries/RentalUtils.sol";
13: import {Signer} from "@src/packages/Signer.sol";
14: import {Reclaimer} from "@src/packages/Reclaimer.sol";
15: import {Accumulator} from "@src/packages/Accumulator.sol";
16: import {Storage} from "@src/modules/Storage.sol";
17: import {PaymentEscrow} from "@src/modules/PaymentEscrow.sol";
18: import {Errors} from "@src/libraries/Errors.sol";
19: import {Events} from "@src/libraries/Events.sol";
20: import {
21:     Item,
22:     RentalOrder,
23:     Hook,
24:     OrderType,
25:     ItemType,
26:     RentalId,
27:     RentalAssetUpdate
28: } from "@src/libraries/RentalStructs.sol";
29: 
30: /**
31:  * @title Stop
32:  * @notice Acts as an interface for all behavior related to stoping a rental.
33:  */
34: contract Stop is Policy, Signer, Reclaimer, Accumulator {
35:     using RentalUtils for Item;
36:     using RentalUtils for Item[];
37:     using RentalUtils for OrderType;
38: 
39:     /////////////////////////////////////////////////////////////////////////////////
40:     //                         Kernel Policy Configuration                         //
41:     /////////////////////////////////////////////////////////////////////////////////
42: 
43:     // Modules that the policy depends on.
44:     Storage public STORE;
45:     PaymentEscrow public ESCRW;
46: 
47:     /**
48:      * @dev Instantiate this contract as a policy.
49:      *
50:      * @param kernel_ Address of the kernel contract.
51:      */
52:     constructor(Kernel kernel_) Policy(kernel_) Signer() Reclaimer() {}
53: 
54:     /**
55:      * @notice Upon policy activation, configures the modules that the policy depends on.
56:      *         If a module is ever upgraded that this policy depends on, the kernel will
57:      *         call this function again to ensure this policy has the current address
58:      *         of the module.
59:      *
60:      * @return dependencies Array of keycodes which represent modules that
61:      *                      this policy depends on.
62:      */
63:     function configureDependencies()
64:         external
65:         override
66:         onlyKernel
67:         returns (Keycode[] memory dependencies)
68:     {
69:         dependencies = new Keycode[](2);
70: 
71:         dependencies[0] = toKeycode("STORE");
72:         STORE = Storage(getModuleAddress(toKeycode("STORE")));
73: 
74:         dependencies[1] = toKeycode("ESCRW");
75:         ESCRW = PaymentEscrow(getModuleAddress(toKeycode("ESCRW")));
76:     }
77: 
78:     /**
79:      * @notice Upon policy activation, permissions are requested from the kernel to access
80:      *         particular keycode <> function selector pairs. Once these permissions are
81:      *         granted, they do not change and can only be revoked when the policy is
82:      *         deactivated by the kernel.
83:      *
84:      * @return requests Array of keycode <> function selector pairs which represent
85:      *                  permissions for the policy.
86:      */
87:     function requestPermissions()
88:         external
89:         view
90:         override
91:         onlyKernel
92:         returns (Permissions[] memory requests)
93:     {
94:         requests = new Permissions[](4);
95:         requests[0] = Permissions(toKeycode("STORE"), STORE.removeRentals.selector);
96:         requests[1] = Permissions(toKeycode("STORE"), STORE.removeRentalsBatch.selector);
97:         requests[2] = Permissions(toKeycode("ESCRW"), ESCRW.settlePayment.selector);
98:         requests[3] = Permissions(toKeycode("ESCRW"), ESCRW.settlePaymentBatch.selector);
99:     }
100: 
101:     /////////////////////////////////////////////////////////////////////////////////
102:     //                            Internal Functions                               //
103:     /////////////////////////////////////////////////////////////////////////////////
104: 
105:     /**
106:      * @dev Helper function to emit an event which signals a rental order has stopped.
107:      *
108:      * @param seaportOrderHash Order hash of the seaport order.
109:      * @param stopper Address which stopped the rental order.
110:      */
111:     function _emitRentalOrderStopped(bytes32 seaportOrderHash, address stopper) internal {
112:         // Wmit the event.
113:         emit Events.RentalOrderStopped(seaportOrderHash, stopper);
114:     }
115: 
116:     /**
117:      * @dev Validates that a rental order can be stopped. Whether an order
118:      *      can be stopped is dependent on the type of order. BASE orders can
119:      *      be stopped only when the rental has expired. PAY orders can be stopped
120:      *      by the lender at any point in the time.
121:      *
122:      * @param orderType Order type of the rental order to stop.
123:      * @param endTimestamp Timestamp that the rental will end.
124:      * @param expectedLender Address of the initial lender in the order.
125:      */
126:     function _validateRentalCanBeStoped(
127:         OrderType orderType,
128:         uint256 endTimestamp,
129:         address expectedLender
130:     ) internal view {
131:         // Determine if the order has expired.
132:         bool hasExpired = endTimestamp <= block.timestamp;
133: 
134:         // Determine if the fulfiller is the lender of the order.
135:         bool isLender = expectedLender == msg.sender;
136: 
137:         // BASE orders processing.
138:         if (orderType.isBaseOrder()) {
139:             // check that the period for the rental order has expired.
140:             if (!hasExpired) {
141:                 revert Errors.StopPolicy_CannotStopOrder(block.timestamp, msg.sender);
142:             }
143:         }
144:         // PAY order processing.
145:         else if (orderType.isPayOrder()) {
146:             // If the stopper is the lender, then it doesnt matter whether the rental
147:             // has expired. But if the stopper is not the lender, then the rental must have expired.
148:             if (!isLender && (!hasExpired)) {
149:                 revert Errors.StopPolicy_CannotStopOrder(block.timestamp, msg.sender);
150:             }
151:         }
152:         // Revert if given an invalid order type.
153:         else {
154:             revert Errors.Shared_OrderTypeNotSupported(uint8(orderType));
155:         }
156:     }
157: 
158:     /**
159:      * @dev Since the stop policy is an enabled Gnosis Safe module on all rental safes, it
160:      *      can be used to execute a transaction directly from the rental safe which retrieves
161:      *      the rented assets. This call bypasses the guard that prevents the assets from being
162:      *      transferred.
163:      *
164:      * @param order Rental order to reclaim the items for.
165:      */
166:     function _reclaimRentedItems(RentalOrder memory order) internal {
167:         // Transfer ERC721s from the renter back to lender.
168:         bool success = ISafe(order.rentalWallet).execTransactionFromModule(
169:             // Stop policy inherits the reclaimer package.
170:             address(this),
171:             // value.
172:             0,
173:             // The encoded call to the `reclaimRentalOrder` function.
174:             abi.encodeWithSelector(this.reclaimRentalOrder.selector, order),
175:             // Safe must delegate call to the stop policy so that it is the msg.sender.
176:             Enum.Operation.DelegateCall
177:         );
178: 
179:         // Assert that the transfer back to the lender was successful.
180:         if (!success) {
181:             revert Errors.StopPolicy_ReclaimFailed();
182:         }
183:     }
184: 
185:     /**
186:      * @dev When a rental order is stopped, process each hook one by one but only if
187:      *      the hook's status is set to execute on a rental stop.
188:      *
189:      * @param hooks        Array of hooks to process for the order.
190:      * @param rentalItems  Array of rental items which are referenced by the hooks
191:      * @param rentalWallet Address of the rental wallet which is the current owner
192:      *                     of the rented assets.
193:      */
194:     function _removeHooks(
195:         Hook[] calldata hooks,
196:         Item[] calldata rentalItems,
197:         address rentalWallet
198:     ) internal {
199:         // Define hook target, item index, and item.
200:         address target;
201:         uint256 itemIndex;
202:         Item memory item;
203: 
204:         // Loop through each hook in the payload.
205:         for (uint256 i = 0; i < hooks.length; ++i) {
206:             // Get the hook address.
207:             target = hooks[i].target;
208: 
209:             // Check that the hook is reNFT-approved to execute on rental stop.
210:             if (!STORE.hookOnStop(target)) {
211:                 revert Errors.Shared_DisabledHook(target);
212:             }
213: 
214:             // Get the rental item index for this hook.
215:             itemIndex = hooks[i].itemIndex;
216: 
217:             // Get the rental item for this hook.
218:             item = rentalItems[itemIndex];
219: 
220:             // Make sure the item is a rented item.
221:             if (!item.isRental()) {
222:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
223:             }
224: 
225:             // Call the hook with data about the rented item.
226:             try
227:                 IHook(target).onStop(
228:                     rentalWallet,
229:                     item.token,
230:                     item.identifier,
231:                     item.amount,
232:                     hooks[i].extraData
233:                 )
234:             {} catch Error(string memory revertReason) {
235:                 // Revert with reason given.
236:                 revert Errors.Shared_HookFailString(revertReason);
237:             } catch Panic(uint256 errorCode) {
238:                 // Convert solidity panic code to string.
239:                 string memory stringErrorCode = LibString.toString(errorCode);
240: 
241:                 // Revert with panic code.
242:                 revert Errors.Shared_HookFailString(
243:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
244:                 );
245:             } catch (bytes memory revertData) {
246:                 // Fallback to an error that returns the byte data.
247:                 revert Errors.Shared_HookFailBytes(revertData);
248:             }
249:         }
250:     }
251: 
252:     /////////////////////////////////////////////////////////////////////////////////
253:     //                            External Functions                               //
254:     /////////////////////////////////////////////////////////////////////////////////
255: 
256:     /**
257:      * @notice Stops a rental by providing a `RentalOrder` struct. This data does not
258:      *         exist in protocol storage, only the hash of the rental order. However,
259:      *         during rental creation, all data needed to construct the rental order
260:      *         is emitted as an event. A check is then made to ensure that the passed
261:      *         in rental order matches the hash of a rental order in storage.
262:      *
263:      * @param order Rental order to stop.
264:      */
265:     function stopRent(RentalOrder calldata order) external {
266:         // Check that the rental can be stopped.
267:         _validateRentalCanBeStoped(order.orderType, order.endTimestamp, order.lender);
268: 
269:         // Create an accumulator which will hold all of the rental asset updates, consisting of IDs and
270:         // the rented amount. From this point on, new memory cannot be safely allocated until the
271:         // accumulator no longer needs to include elements.
272:         bytes memory rentalAssetUpdates = new bytes(0);
273: 
274:         // Check if each item in the order is a rental. If so, then generate the rental asset update.
275:         // Memory will become safe again after this block.
276:         for (uint256 i; i < order.items.length; ++i) {
277:             if (order.items[i].isRental()) {
278:                 // Insert the rental asset update into the dynamic array.
279:                 _insert(
280:                     rentalAssetUpdates,
281:                     order.items[i].toRentalId(order.rentalWallet),
282:                     order.items[i].amount
283:                 );
284:             }
285:         }
286: 
287:         // Interaction: process hooks so they no longer exist for the renter.
288:         if (order.hooks.length > 0) {
289:             _removeHooks(order.hooks, order.items, order.rentalWallet);
290:         }
291: 
292:         // Interaction: Transfer rentals from the renter back to lender.
293:         _reclaimRentedItems(order);
294: 
295:         // Interaction: Transfer ERC20 payments from the escrow contract to the respective recipients.
296:         ESCRW.settlePayment(order);
297: 
298:         // Interaction: Remove rentals from storage by computing the order hash.
299:         STORE.removeRentals(
300:             _deriveRentalOrderHash(order),
301:             _convertToStatic(rentalAssetUpdates)
302:         );
303: 
304:         // Emit rental order stopped.
305:         _emitRentalOrderStopped(order.seaportOrderHash, msg.sender);
306:     }
307: 
308:     /**
309:      * @notice Stops a batch of rentals by providing an array of `RentalOrder` structs.
310:      *
311:      * @param orders Array of rental orders to stop.
312:      */
313:     function stopRentBatch(RentalOrder[] calldata orders) external {
314:         // Create an array of rental order hashes which will be removed from storage.
315:         bytes32[] memory orderHashes = new bytes32[](orders.length);
316: 
317:         // Create an accumulator which will hold all of the rental asset updates, consisting of IDs and
318:         // the rented amount. From this point on, new memory cannot be safely allocated until the
319:         // accumulator no longer needs to include elements.
320:         bytes memory rentalAssetUpdates = new bytes(0);
321: 
322:         // Process each rental order.
323:         // Memory will become safe after this block.
324:         for (uint256 i = 0; i < orders.length; ++i) {
325:             // Check that the rental can be stopped.
326:             _validateRentalCanBeStoped(
327:                 orders[i].orderType,
328:                 orders[i].endTimestamp,
329:                 orders[i].lender
330:             );
331: 
332:             // Check if each item in the order is a rental. If so, then generate the rental asset update.
333:             for (uint256 j = 0; j < orders[i].items.length; ++j) {
334:                 // Insert the rental asset update into the dynamic array.
335:                 if (orders[i].items[j].isRental()) {
336:                     _insert(
337:                         rentalAssetUpdates,
338:                         orders[i].items[j].toRentalId(orders[i].rentalWallet),
339:                         orders[i].items[j].amount
340:                     );
341:                 }
342:             }
343: 
344:             // Add the order hash to an array.
345:             orderHashes[i] = _deriveRentalOrderHash(orders[i]);
346: 
347:             // Interaction: Process hooks so they no longer exist for the renter.
348:             if (orders[i].hooks.length > 0) {
349:                 _removeHooks(orders[i].hooks, orders[i].items, orders[i].rentalWallet);
350:             }
351: 
352:             // Interaction: Transfer rental assets from the renter back to lender.
353:             _reclaimRentedItems(orders[i]);
354: 
355:             // Emit rental order stopped.
356:             _emitRentalOrderStopped(orderHashes[i], msg.sender);
357:         }
358: 
359:         // Interaction: Transfer ERC20 payments from the escrow contract to the respective recipients.
360:         ESCRW.settlePaymentBatch(orders);
361: 
362:         // Interaction: Remove all rentals from storage.
363:         STORE.removeRentalsBatch(orderHashes, _convertToStatic(rentalAssetUpdates));
364:     }
365: }
366: 

```


*GitHub* : [1](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L1-L1)

```solidity
1: // SPDX-License-Identifier: BUSL-1.1
2: pragma solidity ^0.8.20;
3: 
4: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol";
5: import {toKeycode} from "@src/libraries/KernelUtils.sol";
6: import {Storage} from "@src/modules/Storage.sol";
7: import {PaymentEscrow} from "@src/modules/PaymentEscrow.sol";
8: 
9: /**
10:  * @title Admin
11:  * @notice Acts as an interface for all behavior in the protocol related
12:  *         admin logic. Admin duties include fee management, proxy management,
13:  *         and whitelist management.
14:  */
15: contract Admin is Policy {
16:     /////////////////////////////////////////////////////////////////////////////////
17:     //                         Kernel Policy Configuration                         //
18:     /////////////////////////////////////////////////////////////////////////////////
19: 
20:     // Modules that the policy depends on.
21:     Storage public STORE;
22:     PaymentEscrow public ESCRW;
23: 
24:     /**
25:      * @dev Instantiate this contract as a policy.
26:      *
27:      * @param kernel_ Address of the kernel contract.
28:      */
29:     constructor(Kernel kernel_) Policy(kernel_) {}
30: 
31:     /**
32:      * @notice Upon policy activation, configures the modules that the policy depends on.
33:      *         If a module is ever upgraded that this policy depends on, the kernel will
34:      *         call this function again to ensure this policy has the current address
35:      *         of the module.
36:      *
37:      * @return dependencies Array of keycodes which represent modules that
38:      *                      this policy depends on.
39:      */
40:     function configureDependencies()
41:         external
42:         override
43:         onlyKernel
44:         returns (Keycode[] memory dependencies)
45:     {
46:         dependencies = new Keycode[](2);
47: 
48:         dependencies[0] = toKeycode("STORE");
49:         STORE = Storage(getModuleAddress(toKeycode("STORE")));
50: 
51:         dependencies[1] = toKeycode("ESCRW");
52:         ESCRW = PaymentEscrow(getModuleAddress(toKeycode("ESCRW")));
53:     }
54: 
55:     /**
56:      * @notice Upon policy activation, permissions are requested from the kernel to access
57:      *         particular keycode <> function selector pairs. Once these permissions are
58:      *         granted, they do not change and can only be revoked when the policy is
59:      *         deactivated by the kernel.
60:      *
61:      * @return requests Array of keycode <> function selector pairs which represent
62:      *                  permissions for the policy.
63:      */
64:     function requestPermissions()
65:         external
66:         view
67:         override
68:         onlyKernel
69:         returns (Permissions[] memory requests)
70:     {
71:         requests = new Permissions[](8);
72:         requests[0] = Permissions(
73:             toKeycode("STORE"),
74:             STORE.toggleWhitelistExtension.selector
75:         );
76:         requests[1] = Permissions(
77:             toKeycode("STORE"),
78:             STORE.toggleWhitelistDelegate.selector
79:         );
80:         requests[2] = Permissions(toKeycode("STORE"), STORE.upgrade.selector);
81:         requests[3] = Permissions(toKeycode("STORE"), STORE.freeze.selector);
82: 
83:         requests[4] = Permissions(toKeycode("ESCRW"), ESCRW.skim.selector);
84:         requests[5] = Permissions(toKeycode("ESCRW"), ESCRW.setFee.selector);
85:         requests[6] = Permissions(toKeycode("ESCRW"), ESCRW.upgrade.selector);
86:         requests[7] = Permissions(toKeycode("ESCRW"), ESCRW.freeze.selector);
87:     }
88: 
89:     /////////////////////////////////////////////////////////////////////////////////
90:     //                            External Functions                               //
91:     /////////////////////////////////////////////////////////////////////////////////
92: 
93:     /**
94:      * @notice Toggle whether an address can be delegate called by a rental safe.
95:      *
96:      * @param delegate  Target address for the delegate call.
97:      * @param isEnabled Whether the address can be delegate called.
98:      */
99:     function toggleWhitelistDelegate(
100:         address delegate,
101:         bool isEnabled
102:     ) external onlyRole("ADMIN_ADMIN") {
103:         STORE.toggleWhitelistDelegate(delegate, isEnabled);
104:     }
105: 
106:     /**
107:      * @notice Toggle whether an extension is whitelisted. An extension is any contract
108:      *         which can be added to a rental safe as a Safe module.
109:      *
110:      * @param extension Extension which can be added to a safe.
111:      * @param isEnabled Whether the extension is enabled.
112:      */
113:     function toggleWhitelistExtension(
114:         address extension,
115:         bool isEnabled
116:     ) external onlyRole("ADMIN_ADMIN") {
117:         STORE.toggleWhitelistExtension(extension, isEnabled);
118:     }
119: 
120:     /**
121:      * @notice Upgrades the storage module to a newer implementation. The new
122:      *         implementation contract must adhere to ERC-1822.
123:      *
124:      * @param newImplementation Address of the new implemention.
125:      */
126:     function upgradeStorage(address newImplementation) external onlyRole("ADMIN_ADMIN") {
127:         STORE.upgrade(newImplementation);
128:     }
129: 
130:     /**
131:      * @notice Freezes the storage module so that no proxy upgrades can take place. This
132:      *         action is non-reversible.
133:      */
134:     function freezeStorage() external onlyRole("ADMIN_ADMIN") {
135:         STORE.freeze();
136:     }
137: 
138:     /**
139:      * @notice Upgrades the payment escrow module to a newer implementation.
140:      *         The new implementation contract must adhere to ERC-1822.
141:      *
142:      * @param newImplementation Address of the new implemention.
143:      */
144:     function upgradePaymentEscrow(
145:         address newImplementation
146:     ) external onlyRole("ADMIN_ADMIN") {
147:         ESCRW.upgrade(newImplementation);
148:     }
149: 
150:     /**
151:      * @notice Freezes the payment escrow module so that no proxy upgrades can take
152:      *         place. This action is non-reversible.
153:      */
154:     function freezePaymentEscrow() external onlyRole("ADMIN_ADMIN") {
155:         ESCRW.freeze();
156:     }
157: 
158:     /**
159:      * @notice Skims all protocol fees from the escrow module to the target address.
160:      *
161:      * @param token Token address which denominates the fee.
162:      * @param to    Destination address to send the tokens.
163:      */
164:     function skim(address token, address to) external onlyRole("ADMIN_ADMIN") {
165:         ESCRW.skim(token, to);
166:     }
167: 
168:     /**
169:      * @notice Sets the protocol fee numerator. Numerator cannot be greater than 10,000.
170:      *
171:      * @param feeNumerator Numerator for the fee.
172:      */
173:     function setFee(uint256 feeNumerator) external onlyRole("ADMIN_ADMIN") {
174:         ESCRW.setFee(feeNumerator);
175:     }
176: }
177: 

```


*GitHub* : [1](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L1-L1)

```solidity
1: // SPDX-License-Identifier: BUSL-1.1
2: pragma solidity ^0.8.20;
3: 
4: import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
5: 
6: import {Kernel, Module, Keycode} from "@src/Kernel.sol";
7: import {Proxiable} from "@src/proxy/Proxiable.sol";
8: import {
9:     RentalOrder,
10:     Item,
11:     ItemType,
12:     SettleTo,
13:     OrderType
14: } from "@src/libraries/RentalStructs.sol";
15: import {Errors} from "@src/libraries/Errors.sol";
16: import {Events} from "@src/libraries/Events.sol";
17: import {RentalUtils} from "@src/libraries/RentalUtils.sol";
18: 
19: /**
20:  * @title PaymentEscrowBase
21:  * @notice Storage exists in its own base contract to avoid storage slot mismatch during upgrades.
22:  */
23: contract PaymentEscrowBase {
24:     // Keeps a record of the current token balances in the escrow.
25:     mapping(address token => uint256 amount) public balanceOf;
26: 
27:     // Fee percentage taken from payments.
28:     uint256 public fee;
29: }
30: 
31: /**
32:  * @title PaymentEscrow
33:  * @notice Module dedicated to escrowing rental payments while rentals are active. When
34:  *         rentals are stopped, this module will determine payouts to all parties and a
35:  *         fee will be reserved to be withdrawn later by a protocol admin.
36:  */
37: contract PaymentEscrow is Proxiable, Module, PaymentEscrowBase {
38:     using RentalUtils for Item;
39:     using RentalUtils for OrderType;
40: 
41:     /////////////////////////////////////////////////////////////////////////////////
42:     //                         Kernel Module Configuration                         //
43:     /////////////////////////////////////////////////////////////////////////////////
44: 
45:     /**
46:      * @dev Instantiate this contract as a module. When using a proxy, the kernel address
47:      *      should be set to address(0).
48:      *
49:      * @param kernel_ Address of the kernel contract.
50:      */
51:     constructor(Kernel kernel_) Module(kernel_) {}
52: 
53:     /**
54:      * @notice Instantiates this contract as a module via a proxy.
55:      *
56:      * @param kernel_ Address of the kernel contract.
57:      */
58:     function MODULE_PROXY_INSTANTIATION(
59:         Kernel kernel_
60:     ) external onlyByProxy onlyUninitialized {
61:         kernel = kernel_;
62:         initialized = true;
63:     }
64: 
65:     /**
66:      * @notice Specifies which version of a module is being implemented.
67:      */
68:     function VERSION() external pure override returns (uint8 major, uint8 minor) {
69:         return (1, 0);
70:     }
71: 
72:     /**
73:      * @notice Defines the keycode for this module.
74:      */
75:     function KEYCODE() public pure override returns (Keycode) {
76:         return Keycode.wrap("ESCRW");
77:     }
78: 
79:     /////////////////////////////////////////////////////////////////////////////////
80:     //                            Internal Functions                               //
81:     /////////////////////////////////////////////////////////////////////////////////
82: 
83:     /**
84:      * @dev Calculates the fee based on the fee numerator set by an admin.
85:      *
86:      * @param amount Amount for which to calculate the fee.
87:      */
88:     function _calculateFee(uint256 amount) internal view returns (uint256) {
89:         // Uses 10,000 as a denominator for the fee.
90:         return (amount * fee) / 10000;
91:     }
92: 
93:     /**
94:      * @dev Safe transfer for ERC20 tokens that do not consistently renturn true/false.
95:      *
96:      * @param token Asset address which is being sent.
97:      * @param to    Destination address for the transfer.
98:      * @param value Amount of the asset being transferred.
99:      */
100:     function _safeTransfer(address token, address to, uint256 value) internal {
101:         // Call transfer() on the token.
102:         (bool success, bytes memory data) = token.call(
103:             abi.encodeWithSelector(IERC20.transfer.selector, to, value)
104:         );
105: 
106:         // Because both reverting and returning false are allowed by the ERC20 standard
107:         // to indicate a failed transfer, we must handle both cases.
108:         //
109:         // If success is false, the ERC20 contract reverted.
110:         //
111:         // If success is true, we must check if return data was provided. If no return
112:         // data is provided, then no revert occurred. But, if return data is provided,
113:         // then it must be decoded into a bool which will indicate the success of the
114:         // transfer.
115:         if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
116:             revert Errors.PaymentEscrowModule_PaymentTransferFailed(token, to, value);
117:         }
118:     }
119: 
120:     /**
121:      * @dev Calculates the pro-rata split based on the amount of time that has elapsed in
122:      *      a rental order. If there are not enough funds to split perfectly, rounding is
123:      *      done to make the split as fair as possible.
124:      *
125:      * @param amount      Amount of tokens for which to calculate the split.
126:      * @param elapsedTime Elapsed time since the rental started.
127:      * @param totalTime   Total time window of the rental from start to end.
128:      *
129:      * @return renterAmount Payment amount to send to the renter.
130:      * @return lenderAmount Payment amoutn to send to the lender.
131:      */
132:     function _calculatePaymentProRata(
133:         uint256 amount,
134:         uint256 elapsedTime,
135:         uint256 totalTime
136:     ) internal pure returns (uint256 renterAmount, uint256 lenderAmount) {
137:         // Calculate the numerator and adjust by a multiple of 1000.
138:         uint256 numerator = (amount * elapsedTime) * 1000;
139: 
140:         // Calculate the result, but bump by 500 to add a rounding adjustment. Then,
141:         // reduce by a multiple of 1000.
142:         renterAmount = ((numerator / totalTime) + 500) / 1000;
143: 
144:         // Calculate lender amount from renter amount so no tokens are left behind.
145:         lenderAmount = amount - renterAmount;
146:     }
147: 
148:     /**
149:      * @dev Settles a payment via a pro-rata split. After payments are calculated, they
150:      *      are transferred to their respective recipients.
151:      *
152:      * @param token       Token address for which to settle a payment.
153:      * @param amount      Amount of the token to settle.
154:      * @param lender      Lender account.
155:      * @param renter      Renter accoutn.
156:      * @param elapsedTime Elapsed time since the rental started.
157:      * @param totalTime   Total time window of the rental from start to end.
158:      */
159:     function _settlePaymentProRata(
160:         address token,
161:         uint256 amount,
162:         address lender,
163:         address renter,
164:         uint256 elapsedTime,
165:         uint256 totalTime
166:     ) internal {
167:         // Calculate the pro-rata payment for renter and lender.
168:         (uint256 renterAmount, uint256 lenderAmount) = _calculatePaymentProRata(
169:             amount,
170:             elapsedTime,
171:             totalTime
172:         );
173: 
174:         // Send the lender portion of the payment.
175:         _safeTransfer(token, lender, lenderAmount);
176: 
177:         // Send the renter portion of the payment.
178:         _safeTransfer(token, renter, renterAmount);
179:     }
180: 
181:     /**
182:      * @dev Settles a payment by sending the full amount to one address.
183:      *
184:      * @param token    Token address for which to settle a payment.
185:      * @param amount   Amount of the token to settle.
186:      * @param settleTo Specifies whether to settle to the lender or the renter.
187:      * @param lender   Lender account.
188:      * @param renter   Renter account.
189:      */
190:     function _settlePaymentInFull(
191:         address token,
192:         uint256 amount,
193:         SettleTo settleTo,
194:         address lender,
195:         address renter
196:     ) internal {
197:         // Determine the address that this payment will settle to.
198:         address settleToAddress = settleTo == SettleTo.LENDER ? lender : renter;
199: 
200:         // Send the payment.
201:         _safeTransfer(token, settleToAddress, amount);
202:     }
203: 
204:     /**
205:      * @dev Settles alls payments contained in the given item. Uses a pro-rata or in full
206:      *      scheme depending on the order type and when the order was stopped.
207:      *
208:      * @param items     Items present in the order.
209:      * @param orderType Type of the order.
210:      * @param lender    Lender account.
211:      * @param renter    Renter account.
212:      * @param start     Timestamp that the rental began.
213:      * @param end       Timestamp that the rental expires at.
214:      */
215:     function _settlePayment(
216:         Item[] calldata items,
217:         OrderType orderType,
218:         address lender,
219:         address renter,
220:         uint256 start,
221:         uint256 end
222:     ) internal {
223:         // Calculate the time values.
224:         uint256 elapsedTime = block.timestamp - start;
225:         uint256 totalTime = end - start;
226: 
227:         // Determine whether the rental order has ended.
228:         bool isRentalOver = elapsedTime >= totalTime;
229: 
230:         // Loop through each item in the order.
231:         for (uint256 i = 0; i < items.length; ++i) {
232:             // Get the item.
233:             Item memory item = items[i];
234: 
235:             // Check that the item is a payment.
236:             if (item.isERC20()) {
237:                 // Set a placeholder payment amount which can be reduced in the
238:                 // presence of a fee.
239:                 uint256 paymentAmount = item.amount;
240: 
241:                 // Take a fee on the payment amount if the fee is on.
242:                 if (fee != 0) {
243:                     // Calculate the new fee.
244:                     uint256 paymentFee = _calculateFee(paymentAmount);
245: 
246:                     // Adjust the payment amount by the fee.
247:                     paymentAmount -= paymentFee;
248:                 }
249: 
250:                 // Effect: Decrease the token balance. Use the payment amount pre-fee
251:                 // so that fees can be taken.
252:                 _decreaseDeposit(item.token, item.amount);
253: 
254:                 // If its a PAY order but the rental hasn't ended yet.
255:                 if (orderType.isPayOrder() && !isRentalOver) {
256:                     // Interaction: a PAY order which hasnt ended yet. Payout is pro-rata.
257:                     _settlePaymentProRata(
258:                         item.token,
259:                         paymentAmount,
260:                         lender,
261:                         renter,
262:                         elapsedTime,
263:                         totalTime
264:                     );
265:                 }
266:                 // If its a PAY order and the rental is over, or, if its a BASE order.
267:                 else if (
268:                     (orderType.isPayOrder() && isRentalOver) || orderType.isBaseOrder()
269:                 ) {
270:                     // Interaction: a pay order or base order which has ended. Payout is in full.
271:                     _settlePaymentInFull(
272:                         item.token,
273:                         paymentAmount,
274:                         item.settleTo,
275:                         lender,
276:                         renter
277:                     );
278:                 } else {
279:                     revert Errors.Shared_OrderTypeNotSupported(uint8(orderType));
280:                 }
281:             }
282:         }
283:     }
284: 
285:     /**
286:      * @dev Decreases the tracked token balance of a particular token on the payment
287:      *      escrow contract.
288:      *
289:      * @param token  Token address.
290:      * @param amount Amount to decrease the balance by.
291:      */
292:     function _decreaseDeposit(address token, uint256 amount) internal {
293:         // Directly decrease the synced balance.
294:         balanceOf[token] -= amount;
295:     }
296: 
297:     /**
298:      * @dev Increases the tracked token balance of a particular token on the payment
299:      *      escrow contract.
300:      *
301:      * @param token  Token address.
302:      * @param amount Amount to increase the balance by.
303:      */
304:     function _increaseDeposit(address token, uint256 amount) internal {
305:         // Directly increase the synced balance.
306:         balanceOf[token] += amount;
307:     }
308: 
309:     /////////////////////////////////////////////////////////////////////////////////
310:     //                            External Functions                               //
311:     /////////////////////////////////////////////////////////////////////////////////
312: 
313:     /**
314:      * @notice Settles the payment for a rental order by transferring all items marked as
315:      *         payments to their destination accounts. During the settlement process, if
316:      *         active, a fee is taken on the payment.
317:      *
318:      * @param order Rental order for which to settle a payment.
319:      */
320:     function settlePayment(RentalOrder calldata order) external onlyByProxy permissioned {
321:         // Settle all payments for the order.
322:         _settlePayment(
323:             order.items,
324:             order.orderType,
325:             order.lender,
326:             order.renter,
327:             order.startTimestamp,
328:             order.endTimestamp
329:         );
330:     }
331: 
332:     /**
333:      * @notice Settles the payments for multiple orders by looping through each one.
334:      *
335:      * @param orders Rental ordesr for which to settle payments.
336:      */
337:     function settlePaymentBatch(
338:         RentalOrder[] calldata orders
339:     ) external onlyByProxy permissioned {
340:         // Loop through each order.
341:         for (uint256 i = 0; i < orders.length; ++i) {
342:             // Settle all payments for the order.
343:             _settlePayment(
344:                 orders[i].items,
345:                 orders[i].orderType,
346:                 orders[i].lender,
347:                 orders[i].renter,
348:                 orders[i].startTimestamp,
349:                 orders[i].endTimestamp
350:             );
351:         }
352:     }
353: 
354:     /**
355:      * @notice When fungible tokens are transferred to the payment escrow contract,
356:      *         their balances should be increased.
357:      *
358:      * @param token  Token address for the asset.
359:      * @param amount Amount of the token transferred to the escrow
360:      */
361:     function increaseDeposit(
362:         address token,
363:         uint256 amount
364:     ) external onlyByProxy permissioned {
365:         // Cannot accept a payment of zero.
366:         if (amount == 0) {
367:             revert Errors.PaymentEscrow_ZeroPayment();
368:         }
369: 
370:         // Increase the deposit
371:         _increaseDeposit(token, amount);
372:     }
373: 
374:     /**
375:      * @notice Sets the numerator for the fee. The denominator will always be set at
376:      *         10,000.
377:      *
378:      * @param feeNumerator Numerator of the fee.
379:      */
380:     function setFee(uint256 feeNumerator) external onlyByProxy permissioned {
381:         // Cannot accept a fee numerator greater than 10000.
382:         if (feeNumerator > 10000) {
383:             revert Errors.PaymentEscrow_InvalidFeeNumerator();
384:         }
385: 
386:         // Set the fee.
387:         fee = feeNumerator;
388:     }
389: 
390:     /**
391:      * @notice Used to collect protocol fees. In addition, if funds are accidentally sent
392:      *         to the payment escrow contract, this function can be used to skim them off.
393:      *
394:      * @param token Address of the token to skim.
395:      * @param to    Address to send the collected tokens.
396:      */
397:     function skim(address token, address to) external onlyByProxy permissioned {
398:         // Fetch the currently synced balance of the escrow.
399:         uint256 syncedBalance = balanceOf[token];
400: 
401:         // Fetch the true token balance of the escrow.
402:         uint256 trueBalance = IERC20(token).balanceOf(address(this));
403: 
404:         // Calculate the amount to skim.
405:         uint256 skimmedBalance = trueBalance - syncedBalance;
406: 
407:         // Send the difference to the specified address.
408:         _safeTransfer(token, to, skimmedBalance);
409: 
410:         // Emit event with fees taken.
411:         emit Events.FeeTaken(token, skimmedBalance);
412:     }
413: 
414:     /**
415:      * @notice Upgrades the contract to a different implementation. This implementation
416:      *         contract must be compatible with ERC-1822 or else the upgrade will fail.
417:      *
418:      * @param newImplementation Address of the implementation contract to upgrade to.
419:      */
420:     function upgrade(address newImplementation) external onlyByProxy permissioned {
421:         // _upgrade is implemented in the Proxiable contract.
422:         _upgrade(newImplementation);
423:     }
424: 
425:     /**
426:      * @notice Freezes the contract which prevents upgrading the implementation contract.
427:      *         There is no way to unfreeze once a contract has been frozen.
428:      */
429:     function freeze() external onlyByProxy permissioned {
430:         // _freeze is implemented in the Proxiable contract.
431:         _freeze();
432:     }
433: }
434: 

```


*GitHub* : [1](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L1-L1)

```solidity
1: // SPDX-License-Identifier: BUSL-1.1
2: pragma solidity ^0.8.20;
3: 
4: import {IERC721} from "@openzeppelin-contracts/token/ERC721/IERC721.sol";
5: import {IERC1155} from "@openzeppelin-contracts/token/ERC1155/IERC1155.sol";
6: 
7: import {RentalOrder, Item, ItemType} from "@src/libraries/RentalStructs.sol";
8: import {Errors} from "@src/libraries/Errors.sol";
9: 
10: /**
11:  * @title Reclaimer
12:  * @notice Retrieves rented assets from a wallet contract once a rental has been
13:  *         stopped, and transfers them to the proper recipient.
14:  */
15: abstract contract Reclaimer {
16:     // The original address that this contract was deployed with
17:     address private immutable original;
18: 
19:     /**
20:      * @dev Use the constructor to store the original deployment address.
21:      */
22:     constructor() {
23:         original = address(this);
24:     }
25: 
26:     /**
27:      * @dev Helper function to transfer an ERC721 token.
28:      *
29:      * @param item      Item which will be transferred.
30:      * @param recipient Address which will receive the token.
31:      */
32:     function _transferERC721(Item memory item, address recipient) private {
33:         IERC721(item.token).safeTransferFrom(address(this), recipient, item.identifier);
34:     }
35: 
36:     /**
37:      * @dev Helper function to transfer an ERC1155 token.
38:      *
39:      * @param item      Item which will be transferred.
40:      * @param recipient Address which will receive the token.
41:      */
42:     function _transferERC1155(Item memory item, address recipient) private {
43:         IERC1155(item.token).safeTransferFrom(
44:             address(this),
45:             recipient,
46:             item.identifier,
47:             item.amount,
48:             ""
49:         );
50:     }
51: 
52:     /**
53:      * @notice Reclaims the assets that are currently owned by a rental safe.
54:      *         This function is intended to be delegate called by the safe.
55:      *
56:      *         NOTE: At first, it may seem that this function can be used to exploit
57:      *         the safe, since this is an external function that can transfer tokens
58:      *         out of a rental safe, so long as the caller is:
59:      *             1) Using delegate call to extract the assets
60:      *             2) The rental safe that holds those assets
61:      *
62:      *         This exploit is prevented because delegate calls from the rental safe can
63:      *         only be made to addresses which have been explicitly whitelisted by the
64:      *         Admin policy. Further, since the Stop policy is a whitelisted module on
65:      *         the safe, `reclaimRentalOrder()` can only be called via the context of the
66:      *         Stop policy contract, which prevents unauthorized reclaiming.
67:      *
68:      * @param rentalOrder Order which will have its contained items reclaimed by the
69:      *                    recipient parties.
70:      */
71:     function reclaimRentalOrder(RentalOrder calldata rentalOrder) external {
72:         // This contract address must be in the context of another address.
73:         if (address(this) == original) {
74:             revert Errors.ReclaimerPackage_OnlyDelegateCallAllowed();
75:         }
76: 
77:         // Only the rental wallet specified in the order can be the address that
78:         // initates the reclaim. In the context of a delegate call, address(this)
79:         // will be the safe.
80:         if (address(this) != rentalOrder.rentalWallet) {
81:             revert Errors.ReclaimerPackage_OnlyRentalSafeAllowed(
82:                 rentalOrder.rentalWallet
83:             );
84:         }
85: 
86:         // Get a count for the number of items.
87:         uint256 itemCount = rentalOrder.items.length;
88: 
89:         // Transfer each item if it is a rented asset.
90:         for (uint256 i = 0; i < itemCount; ++i) {
91:             Item memory item = rentalOrder.items[i];
92: 
93:             // Check if the item is an ERC721.
94:             if (item.itemType == ItemType.ERC721)
95:                 _transferERC721(item, rentalOrder.lender);
96: 
97:             // check if the item is an ERC1155.
98:             if (item.itemType == ItemType.ERC1155)
99:                 _transferERC1155(item, rentalOrder.lender);
100:         }
101:     }
102: }
103: 

```


*GitHub* : [1](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L1-L1)

```solidity
1: // SPDX-License-Identifier: BUSL-1.1
2: pragma solidity ^0.8.20;
3: 
4: import {ECDSA} from "@openzeppelin-contracts/utils/cryptography/ECDSA.sol";
5: 
6: import {
7:     RentPayload,
8:     Hook,
9:     RentalOrder,
10:     OrderFulfillment,
11:     OrderMetadata,
12:     Item
13: } from "@src/libraries/RentalStructs.sol";
14: import {Errors} from "@src/libraries/Errors.sol";
15: 
16: /**
17:  * @title Signer
18:  * @notice Contains logic related to signed payloads and signature verification when
19:  *         creating rentals.
20:  */
21: abstract contract Signer {
22:     using ECDSA for bytes32;
23: 
24:     // Declare constants for name and version.
25:     string internal constant _NAME = "ReNFT-Rentals";
26:     string internal constant _VERSION = "1.0.0";
27: 
28:     // Precompute hashes, original chainId, and domain separator on deployment.
29:     bytes32 internal immutable _NAME_HASH;
30:     bytes32 internal immutable _VERSION_HASH;
31:     bytes32 internal immutable _EIP_712_DOMAIN_TYPEHASH;
32:     uint256 internal immutable _CHAIN_ID;
33:     bytes32 internal immutable _DOMAIN_SEPARATOR;
34:     bytes32 internal immutable _ITEM_TYPEHASH;
35:     bytes32 internal immutable _HOOK_TYPEHASH;
36:     bytes32 internal immutable _RENTAL_ORDER_TYPEHASH;
37:     bytes32 internal immutable _ORDER_FULFILLMENT_TYPEHASH;
38:     bytes32 internal immutable _ORDER_METADATA_TYPEHASH;
39:     bytes32 internal immutable _RENT_PAYLOAD_TYPEHASH;
40: 
41:     /**
42:      * @dev Sets up the type hashes and sets the chain ID.
43:      */
44:     constructor() {
45:         // Derive name, version, and EIP-712 typehashes.
46:         (
47:             _NAME_HASH,
48:             _VERSION_HASH,
49:             _EIP_712_DOMAIN_TYPEHASH,
50:             _DOMAIN_SEPARATOR
51:         ) = _deriveTypehashes();
52: 
53:         // Derive name and version hashes alongside required EIP-712 typehashes.
54:         (
55:             _ITEM_TYPEHASH,
56:             _HOOK_TYPEHASH,
57:             _RENTAL_ORDER_TYPEHASH,
58:             _ORDER_FULFILLMENT_TYPEHASH,
59:             _ORDER_METADATA_TYPEHASH,
60:             _RENT_PAYLOAD_TYPEHASH
61:         ) = _deriveRentalTypehashes();
62: 
63:         // Store the current chainId and derive the current domain separator.
64:         _CHAIN_ID = block.chainid;
65:     }
66: 
67:     /**
68:      * @dev Validates that the expected fulfiller of the order is the same as the address
69:      *      executed the order. This check is meant to prevent order sniping where one
70:      *      party receives a server-side signature but another party intercepts the
71:      *      signature and uses it.
72:      *
73:      * @param intendedFulfiller Address that was expected to execute the order.
74:      * @param actualFulfiller   Address that actually executed the order.
75:      */
76:     function _validateFulfiller(
77:         address intendedFulfiller,
78:         address actualFulfiller
79:     ) internal pure {
80:         // Check actual fulfiller against the intended fulfiller.
81:         if (intendedFulfiller != actualFulfiller) {
82:             revert Errors.SignerPackage_UnauthorizedFulfiller(
83:                 actualFulfiller,
84:                 intendedFulfiller
85:             );
86:         }
87:     }
88: 
89:     /**
90:      * @dev Validates that the server-side signature has not expired.
91:      *
92:      * @param expiration Expiration time of the signature.
93:      */
94:     function _validateProtocolSignatureExpiration(uint256 expiration) internal view {
95:         // Check that the signature provided by the protocol signer has not expired.
96:         if (block.timestamp > expiration) {
97:             revert Errors.SignerPackage_SignatureExpired(block.timestamp, expiration);
98:         }
99:     }
100: 
101:     /**
102:      * @dev Recovers the signer of the payload hash.
103:      *
104:      * @param payloadHash The payload hash which was signed.
105:      * @param signature   The signature data for the payload hash.
106:      */
107:     function _recoverSignerFromPayload(
108:         bytes32 payloadHash,
109:         bytes memory signature
110:     ) internal view returns (address) {
111:         // Derive original EIP-712 digest using domain separator and order hash.
112:         bytes32 digest = _DOMAIN_SEPARATOR.toTypedDataHash(payloadHash);
113: 
114:         // Recover the signer address of the signature.
115:         return digest.recover(signature);
116:     }
117: 
118:     /**
119:      * @dev Derives the hash of a given item using a type hash.
120:      *
121:      * @param item Item to hash.
122:      *
123:      * @return The hash of the item.
124:      */
125:     function _deriveItemHash(Item memory item) internal view returns (bytes32) {
126:         // Derive and return the item as specified by EIP-712.
127:         return
128:             keccak256(
129:                 abi.encode(
130:                     _ITEM_TYPEHASH,
131:                     item.itemType,
132:                     item.settleTo,
133:                     item.token,
134:                     item.amount,
135:                     item.identifier
136:                 )
137:             );
138:     }
139: 
140:     /**
141:      * @dev Derives the hash of a given hook using a type hash.
142:      *
143:      * @param hook Hook to hash.
144:      *
145:      * @return The hash of the hook.
146:      */
147:     function _deriveHookHash(Hook memory hook) internal view returns (bytes32) {
148:         // Derive and return the hook as specified by EIP-712.
149:         return
150:             keccak256(
151:                 abi.encode(_HOOK_TYPEHASH, hook.target, hook.itemIndex, hook.extraData)
152:             );
153:     }
154: 
155:     /**
156:      * @dev Derives the hash of a given rental order using a type hash.
157:      *
158:      * @param order Rental order to hash.
159:      *
160:      * @return The hash of the rental order.
161:      */
162:     function _deriveRentalOrderHash(
163:         RentalOrder memory order
164:     ) internal view returns (bytes32) {
165:         // Create arrays for items and hooks.
166:         bytes32[] memory itemHashes = new bytes32[](order.items.length);
167:         bytes32[] memory hookHashes = new bytes32[](order.hooks.length);
168: 
169:         // Iterate over each item.
170:         for (uint256 i = 0; i < order.items.length; ++i) {
171:             // Hash the item.
172:             itemHashes[i] = _deriveItemHash(order.items[i]);
173:         }
174: 
175:         // Iterate over each hook.
176:         for (uint256 i = 0; i < order.hooks.length; ++i) {
177:             // Hash the hook.
178:             hookHashes[i] = _deriveHookHash(order.hooks[i]);
179:         }
180: 
181:         return
182:             keccak256(
183:                 abi.encode(
184:                     _RENTAL_ORDER_TYPEHASH,
185:                     order.seaportOrderHash,
186:                     keccak256(abi.encodePacked(itemHashes)),
187:                     keccak256(abi.encodePacked(hookHashes)),
188:                     order.orderType,
189:                     order.lender,
190:                     order.renter,
191:                     order.startTimestamp,
192:                     order.endTimestamp
193:                 )
194:             );
195:     }
196: 
197:     /**
198:      * @dev Derives the hash of a given fulfillment using a type hash.
199:      *
200:      * @param fulfillment Order fulfillment to hash.
201:      *
202:      * @return The hash of the order fulfillment.
203:      */
204:     function _deriveOrderFulfillmentHash(
205:         OrderFulfillment memory fulfillment
206:     ) internal view returns (bytes32) {
207:         // Derive and return the fulfilmment hash as specified by EIP-712
208:         return keccak256(abi.encode(_ORDER_FULFILLMENT_TYPEHASH, fulfillment.recipient));
209:     }
210: 
211:     /**
212:      * @dev Derives the hash of a given order metadata using a type hash.
213:      *
214:      * @param metadata Order metadata to hash.
215:      *
216:      * @return The hash of the order metadata.
217:      */
218:     function _deriveOrderMetadataHash(
219:         OrderMetadata memory metadata
220:     ) internal view returns (bytes32) {
221:         // Create array for hooks.
222:         bytes32[] memory hookHashes = new bytes32[](metadata.hooks.length);
223: 
224:         // Iterate over each hook.
225:         for (uint256 i = 0; i < metadata.hooks.length; ++i) {
226:             // Hash the hook
227:             hookHashes[i] = _deriveHookHash(metadata.hooks[i]);
228:         }
229: 
230:         // Derive and return the metadata hash as specified by EIP-712.
231:         return
232:             keccak256(
233:                 abi.encode(
234:                     _ORDER_METADATA_TYPEHASH,
235:                     metadata.rentDuration,
236:                     keccak256(abi.encodePacked(hookHashes))
237:                 )
238:             );
239:     }
240: 
241:     /**
242:      * @dev Derives the hash of a given payload using a type hash.
243:      *
244:      * @param payload Rent payload to hash.
245:      *
246:      * @return The hash of the rent payload.
247:      */
248:     function _deriveRentPayloadHash(
249:         RentPayload memory payload
250:     ) internal view returns (bytes32) {
251:         // Derive and return the rent payload hash as specified by EIP-712.
252:         return
253:             keccak256(
254:                 abi.encode(
255:                     _RENT_PAYLOAD_TYPEHASH,
256:                     _deriveOrderFulfillmentHash(payload.fulfillment),
257:                     _deriveOrderMetadataHash(payload.metadata),
258:                     payload.expiration,
259:                     payload.intendedFulfiller
260:                 )
261:             );
262:     }
263: 
264:     /**
265:      * @dev Derives the hash of the domain separator.
266:      *
267:      * @param _eip712DomainTypeHash The standard EIP-712 domain type string.
268:      * @param _nameHash             Hash of the contract name.
269:      * @param _versionHash          Hash of the contract version.
270:      *
271:      * @return The hash of the domain separator.
272:      */
273:     function _deriveDomainSeparator(
274:         bytes32 _eip712DomainTypeHash,
275:         bytes32 _nameHash,
276:         bytes32 _versionHash
277:     ) internal view virtual returns (bytes32) {
278:         return
279:             keccak256(
280:                 abi.encode(
281:                     _eip712DomainTypeHash,
282:                     _nameHash,
283:                     _versionHash,
284:                     block.chainid,
285:                     address(this)
286:                 )
287:             );
288:     }
289: 
290:     /**
291:      * @dev Derives the standard EIP-712 type hashes.
292:      *
293:      * @return nameHash             Hash of the contract name.
294:      * @return versionHash          Hash of the contract version.
295:      * @return eip712DomainTypehash Hash of the EIP-712 Domain.
296:      * @return domainSeparator      The constructed domain separator.
297:      */
298:     function _deriveTypehashes()
299:         internal
300:         view
301:         returns (
302:             bytes32 nameHash,
303:             bytes32 versionHash,
304:             bytes32 eip712DomainTypehash,
305:             bytes32 domainSeparator
306:         )
307:     {
308:         // Derive the name type hash.
309:         nameHash = keccak256(bytes(_NAME));
310: 
311:         // Derive the version type hash.
312:         versionHash = keccak256(bytes(_VERSION));
313: 
314:         // Construct the primary EIP-712 domain type string.
315:         eip712DomainTypehash = keccak256(
316:             abi.encodePacked(
317:                 "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
318:             )
319:         );
320: 
321:         // Construct the domain separator.
322:         domainSeparator = _deriveDomainSeparator(
323:             eip712DomainTypehash,
324:             nameHash,
325:             versionHash
326:         );
327:     }
328: 
329:     /**
330:      * @dev Derives the protocol-specific type hashes.
331:      *
332:      * @return itemTypeHash             Type hash of the item.
333:      * @return hookTypeHash             Type hash of the hook.
334:      * @return rentalOrderTypeHash      Type hash of the rental order.
335:      * @return orderFulfillmentTypeHash Type hash of the order fulfillment.
336:      * @return orderMetadataTypeHash    Type hash of the order metadata.
337:      * @return rentPayloadTypeHash      Type hash of the rent payload.
338:      */
339:     function _deriveRentalTypehashes()
340:         internal
341:         pure
342:         returns (
343:             bytes32 itemTypeHash,
344:             bytes32 hookTypeHash,
345:             bytes32 rentalOrderTypeHash,
346:             bytes32 orderFulfillmentTypeHash,
347:             bytes32 orderMetadataTypeHash,
348:             bytes32 rentPayloadTypeHash
349:         )
350:     {
351:         // Construct the Item type string.
352:         bytes memory itemTypeString = abi.encodePacked(
353:             "Item(uint8 itemType,uint8 settleTo,address token,uint256 amount,uint256 identifier)"
354:         );
355: 
356:         // Construct the Hook type string.
357:         bytes memory hookTypeString = abi.encodePacked(
358:             "Hook(address target,uint256 itemIndex,bytes extraData)"
359:         );
360: 
361:         // Construct the RentalOrder type string.
362:         bytes memory rentalOrderTypeString = abi.encodePacked(
363:             "RentalOrder(bytes32 seaportOrderHash,Item[] items,Hook[] hooks,uint8 orderType,address lender,address renter,address rentalWallet,uint256 startTimestamp,uint256 endTimestamp)"
364:         );
365: 
366:         // Derive the Item type hash using the corresponding type string.
367:         itemTypeHash = keccak256(itemTypeString);
368: 
369:         // Derive the Hook type hash using the corresponding type string.
370:         hookTypeHash = keccak256(hookTypeString);
371: 
372:         // Derive the RentalOrder type hash using the corresponding type string.
373:         rentalOrderTypeHash = keccak256(
374:             abi.encode(rentalOrderTypeString, hookTypeString, itemTypeString)
375:         );
376: 
377:         {
378:             // Construct the OrderFulfillment type string.
379:             bytes memory orderFulfillmentTypeString = abi.encodePacked(
380:                 "OrderFulfillment(address recipient)"
381:             );
382: 
383:             // Construct the OrderMetadata type string.
384:             bytes memory orderMetadataTypeString = abi.encodePacked(
385:                 "OrderMetadata(uint8 orderType,uint256 rentDuration,Hook[] hooks,bytes emittedExtraData)"
386:             );
387: 
388:             // Construct the RentPayload type string.
389:             bytes memory rentPayloadTypeString = abi.encodePacked(
390:                 "RentPayload(OrderFulfillment fulfillment,OrderMetadata metadata,uint256 expiration,address intendedFulfiller)"
391:             );
392: 
393:             // Derive RentPayload type hash via combination of relevant type strings.
394:             rentPayloadTypeHash = keccak256(
395:                 abi.encodePacked(
396:                     rentPayloadTypeString,
397:                     orderMetadataTypeString,
398:                     orderFulfillmentTypeString
399:                 )
400:             );
401: 
402:             // Derive the OrderFulfillment type hash using the corresponding type string.
403:             orderFulfillmentTypeHash = keccak256(orderFulfillmentTypeString);
404: 
405:             // Derive the OrderMetadata type hash using the corresponding type string.
406:             orderMetadataTypeHash = keccak256(orderMetadataTypeString);
407:         }
408:     }
409: }
410: 

```


*GitHub* : [1](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L1-L1)

```solidity
1: // SPDX-License-Identifier: BUSL-1.1
2: pragma solidity ^0.8.20;
3: 
4: import {BaseGuard} from "@safe-contracts/base/GuardManager.sol";
5: import {Enum} from "@safe-contracts/common/Enum.sol";
6: import {LibString} from "@solady/utils/LibString.sol";
7: 
8: import {IHook} from "@src/interfaces/IHook.sol";
9: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol";
10: import {toKeycode} from "@src/libraries/KernelUtils.sol";
11: import {Storage} from "@src/modules/Storage.sol";
12: import {
13:     shared_set_approval_for_all_selector,
14:     e721_approve_selector,
15:     e721_safe_transfer_from_1_selector,
16:     e721_safe_transfer_from_2_selector,
17:     e721_transfer_from_selector,
18:     e721_approve_token_id_offset,
19:     e721_safe_transfer_from_1_token_id_offset,
20:     e721_safe_transfer_from_2_token_id_offset,
21:     e721_transfer_from_token_id_offset,
22:     e1155_safe_transfer_from_selector,
23:     e1155_safe_batch_transfer_from_selector,
24:     e1155_safe_transfer_from_token_id_offset,
25:     e1155_safe_batch_transfer_from_token_id_offset,
26:     gnosis_safe_set_guard_selector,
27:     gnosis_safe_enable_module_selector,
28:     gnosis_safe_disable_module_selector,
29:     gnosis_safe_enable_module_offset,
30:     gnosis_safe_disable_module_offset
31: } from "@src/libraries/RentalConstants.sol";
32: import {Errors} from "@src/libraries/Errors.sol";
33: 
34: /**
35:  * @title Guard
36:  * @notice Acts as an interface for all behavior related to guarding transactions
37:  *         that originate from a rental wallet.
38:  */
39: contract Guard is Policy, BaseGuard {
40:     /////////////////////////////////////////////////////////////////////////////////
41:     //                         Kernel Policy Configuration                         //
42:     /////////////////////////////////////////////////////////////////////////////////
43: 
44:     // Modules that the policy depends on.
45:     Storage public STORE;
46: 
47:     /**
48:      * @dev Instantiate this contract as a policy.
49:      *
50:      * @param kernel_ Address of the kernel contract.
51:      */
52:     constructor(Kernel kernel_) Policy(kernel_) {}
53: 
54:     /**
55:      * @notice Upon policy activation, configures the modules that the policy depends on.
56:      *         If a module is ever upgraded that this policy depends on, the kernel will
57:      *         call this function again to ensure this policy has the current address
58:      *         of the module.
59:      *
60:      * @return dependencies Array of keycodes which represent modules that
61:      *                      this policy depends on.
62:      */
63:     function configureDependencies()
64:         external
65:         override
66:         onlyKernel
67:         returns (Keycode[] memory dependencies)
68:     {
69:         dependencies = new Keycode[](1);
70: 
71:         dependencies[0] = toKeycode("STORE");
72:         STORE = Storage(getModuleAddress(toKeycode("STORE")));
73:     }
74: 
75:     /**
76:      * @notice Upon policy activation, permissions are requested from the kernel to access
77:      *         particular keycode <> function selector pairs. Once these permissions are
78:      *         granted, they do not change and can only be revoked when the policy is
79:      *         deactivated by the kernel.
80:      *
81:      * @return requests Array of keycode <> function selector pairs which represent
82:      *                  permissions for the policy.
83:      */
84:     function requestPermissions()
85:         external
86:         view
87:         override
88:         onlyKernel
89:         returns (Permissions[] memory requests)
90:     {
91:         requests = new Permissions[](2);
92:         requests[0] = Permissions(toKeycode("STORE"), STORE.updateHookPath.selector);
93:         requests[1] = Permissions(toKeycode("STORE"), STORE.updateHookStatus.selector);
94:     }
95: 
96:     /////////////////////////////////////////////////////////////////////////////////
97:     //                            Internal Functions                               //
98:     /////////////////////////////////////////////////////////////////////////////////
99: 
100:     /**
101:      * @dev Loads a `bytes32` value from calldata.
102:      *
103:      * @param data   Calldata of the transaction to execute.
104:      * @param offset Byte offset where the value starts.
105:      *
106:      * @return value The value retrieved from the data.
107:      */
108:     function _loadValueFromCalldata(
109:         bytes memory data,
110:         uint256 offset
111:     ) private pure returns (bytes32 value) {
112:         // Load the `uint256` from calldata at the offset.
113:         assembly {
114:             value := mload(add(data, offset))
115:         }
116:     }
117: 
118:     /**
119:      * @dev Reverts if the token is actively rented.
120:      *
121:      * @param selector Function selector which cannot be called
122:      * @param safe     Address of the safe that originated the call
123:      * @param token    Address of the token which is actively rented.
124:      * @param tokenId  ID of the token which is actively rented.
125:      */
126:     function _revertSelectorOnActiveRental(
127:         bytes4 selector,
128:         address safe,
129:         address token,
130:         uint256 tokenId
131:     ) private view {
132:         // Check if the selector is allowed.
133:         if (STORE.isRentedOut(safe, token, tokenId)) {
134:             revert Errors.GuardPolicy_UnauthorizedSelector(selector);
135:         }
136:     }
137: 
138:     /**
139:      * @dev Reverts if the extension is not whitelisted.
140:      *
141:      * @param extension Address of the extension.
142:      */
143:     function _revertNonWhitelistedExtension(address extension) private view {
144:         // Check if the extension is whitelisted.
145:         if (!STORE.whitelistedExtensions(extension)) {
146:             revert Errors.GuardPolicy_UnauthorizedExtension(extension);
147:         }
148:     }
149: 
150:     /**
151:      * @dev Forwards a gnosis safe call to a hook contract for further processing.
152:      *
153:      * @param hook  Address of the hook contract.
154:      * @param safe  Address of the rental wallet that originated the call.
155:      * @param to    Address that the call is directed to.
156:      * @param value Value of ether sent with the call.
157:      * @param data  Calldata to execute.
158:      */
159:     function _forwardToHook(
160:         address hook,
161:         address safe,
162:         address to,
163:         uint256 value,
164:         bytes memory data
165:     ) private {
166:         // Call the `onTransaction` hook function.
167:         try IHook(hook).onTransaction(safe, to, value, data) {} catch Error(
168:             string memory revertReason
169:         ) {
170:             // Revert with reason given.
171:             revert Errors.Shared_HookFailString(revertReason);
172:         } catch Panic(uint256 errorCode) {
173:             // Convert solidity panic code to string.
174:             string memory stringErrorCode = LibString.toString(errorCode);
175: 
176:             // Revert with panic code.
177:             revert Errors.Shared_HookFailString(
178:                 string.concat("Hook reverted: Panic code ", stringErrorCode)
179:             );
180:         } catch (bytes memory revertData) {
181:             // Fallback to an error that returns the byte data.
182:             revert Errors.Shared_HookFailBytes(revertData);
183:         }
184:     }
185: 
186:     /**
187:      * @dev Prevent transactions that involve transferring an ERC721 or ERC1155 in any
188:      *      way, and prevent transactions that involve changing the modules or the
189:      *      guard contract.
190:      *
191:      * @param from Rental safe address that initiated the transaction.
192:      * @param to Address that the data is targetted to.
193:      * @param data Calldata of the transaction.
194:      */
195:     function _checkTransaction(address from, address to, bytes memory data) private view {
196:         bytes4 selector;
197: 
198:         // Load in the function selector.
199:         assembly {
200:             selector := mload(add(data, 0x20))
201:         }
202: 
203:         if (selector == e721_safe_transfer_from_1_selector) {
204:             // Load the token ID from calldata.
205:             uint256 tokenId = uint256(
206:                 _loadValueFromCalldata(data, e721_safe_transfer_from_1_token_id_offset)
207:             );
208: 
209:             // Check if the selector is allowed.
210:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
211:         } else if (selector == e721_safe_transfer_from_2_selector) {
212:             // Load the token ID from calldata.
213:             uint256 tokenId = uint256(
214:                 _loadValueFromCalldata(data, e721_safe_transfer_from_2_token_id_offset)
215:             );
216: 
217:             // Check if the selector is allowed.
218:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
219:         } else if (selector == e721_transfer_from_selector) {
220:             // Load the token ID from calldata.
221:             uint256 tokenId = uint256(
222:                 _loadValueFromCalldata(data, e721_transfer_from_token_id_offset)
223:             );
224: 
225:             // Check if the selector is allowed.
226:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
227:         } else if (selector == e721_approve_selector) {
228:             // Load the token ID from calldata.
229:             uint256 tokenId = uint256(
230:                 _loadValueFromCalldata(data, e721_approve_token_id_offset)
231:             );
232: 
233:             // Check if the selector is allowed.
234:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
235:         } else if (selector == e1155_safe_transfer_from_selector) {
236:             // Load the token ID from calldata.
237:             uint256 tokenId = uint256(
238:                 _loadValueFromCalldata(data, e1155_safe_transfer_from_token_id_offset)
239:             );
240: 
241:             // Check if the selector is allowed.
242:             _revertSelectorOnActiveRental(selector, from, to, tokenId);
243:         } else if (selector == gnosis_safe_enable_module_selector) {
244:             // Load the extension address from calldata.
245:             address extension = address(
246:                 uint160(
247:                     uint256(
248:                         _loadValueFromCalldata(data, gnosis_safe_enable_module_offset)
249:                     )
250:                 )
251:             );
252: 
253:             // Check if the extension is whitelisted.
254:             _revertNonWhitelistedExtension(extension);
255:         } else if (selector == gnosis_safe_disable_module_selector) {
256:             // Load the extension address from calldata.
257:             address extension = address(
258:                 uint160(
259:                     uint256(
260:                         _loadValueFromCalldata(data, gnosis_safe_disable_module_offset)
261:                     )
262:                 )
263:             );
264: 
265:             // Check if the extension is whitelisted.
266:             _revertNonWhitelistedExtension(extension);
267:         } else {
268:             // Revert if the `setApprovalForAll` selector is specified. This selector is
269:             // shared between ERC721 and ERC1155 tokens.
270:             if (selector == shared_set_approval_for_all_selector) {
271:                 revert Errors.GuardPolicy_UnauthorizedSelector(
272:                     shared_set_approval_for_all_selector
273:                 );
274:             }
275: 
276:             // Revert if the `safeBatchTransferFrom` selector is specified. There's no
277:             // cheap way to check if individual items in the batch are rented out.
278:             // Each token ID would require a call to the storage contract to check
279:             // its rental status.
280:             if (selector == e1155_safe_batch_transfer_from_selector) {
281:                 revert Errors.GuardPolicy_UnauthorizedSelector(
282:                     e1155_safe_batch_transfer_from_selector
283:                 );
284:             }
285: 
286:             // Revert if the `setGuard` selector is specified.
287:             if (selector == gnosis_safe_set_guard_selector) {
288:                 revert Errors.GuardPolicy_UnauthorizedSelector(
289:                     gnosis_safe_set_guard_selector
290:                 );
291:             }
292:         }
293:     }
294: 
295:     /////////////////////////////////////////////////////////////////////////////////
296:     //                            External Functions                               //
297:     /////////////////////////////////////////////////////////////////////////////////
298: 
299:     /** @notice Checks a transaction initiated by a rental safe to decide whether
300:      *          it can be allowed or not. During this check, execution control flow
301:      *          will be passed to an external hook contract if one exists for the
302:      *          target contract.
303:      *
304:      * @param to             Destination address of Safe transaction.
305:      * @param value          Ether value of Safe transaction.
306:      * @param data           Data payload of Safe transaction.
307:      * @param operation      Operation type of Safe transaction.
308:      */
309:     function checkTransaction(
310:         address to,
311:         uint256 value,
312:         bytes memory data,
313:         Enum.Operation operation,
314:         uint256,
315:         uint256,
316:         uint256,
317:         address,
318:         address payable,
319:         bytes memory,
320:         address
321:     ) external override {
322:         // Disallow transactions that use delegate call, unless explicitly
323:         // permitted by the protocol.
324:         if (operation == Enum.Operation.DelegateCall && !STORE.whitelistedDelegates(to)) {
325:             revert Errors.GuardPolicy_UnauthorizedDelegateCall(to);
326:         }
327: 
328:         // Require that a function selector exists.
329:         if (data.length < 4) {
330:             revert Errors.GuardPolicy_FunctionSelectorRequired();
331:         }
332: 
333:         // Fetch the hook to interact with for this transaction.
334:         address hook = STORE.contractToHook(to);
335:         bool isActive = STORE.hookOnTransaction(hook);
336: 
337:         // If a hook exists and is enabled, forward the control flow to the hook.
338:         if (hook != address(0) && isActive) {
339:             _forwardToHook(hook, msg.sender, to, value, data);
340:         }
341:         // If no hook exists, use basic tx check.
342:         else {
343:             _checkTransaction(msg.sender, to, data);
344:         }
345:     }
346: 
347:     /**
348:      * @notice Performs any checks after execution. This is left unimplemented.
349:      *
350:      * @param txHash Hash of the transaction.
351:      * @param success Whether the transaction succeeded.
352:      */
353:     function checkAfterExecution(bytes32 txHash, bool success) external override {}
354: 
355:     /**
356:      * @notice Connects a target contract to a hook.
357:      *
358:      * @param to   The destination contract of a call.
359:      * @param hook The hook middleware contract to sit between the call
360:      *             and the destination.
361:      */
362:     function updateHookPath(address to, address hook) external onlyRole("GUARD_ADMIN") {
363:         STORE.updateHookPath(to, hook);
364:     }
365: 
366:     /**
367:      * @notice Toggle the status of a hook contract, which defines the functionality
368:      *         that the hook supports.
369:      *
370:      * @param hook The hook contract address.
371:      * @param bitmap Bitmap of the status.
372:      */
373:     function updateHookStatus(
374:         address hook,
375:         uint8 bitmap
376:     ) external onlyRole("GUARD_ADMIN") {
377:         STORE.updateHookStatus(hook, bitmap);
378:     }
379: }
380: 

```


*GitHub* : [1](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L1-L1)

```solidity
1: // SPDX-License-Identifier: BUSL-1.1
2: pragma solidity ^0.8.20;
3: 
4: import {
5:     toRole,
6:     ensureContract,
7:     ensureValidKeycode,
8:     ensureValidRole
9: } from "@src/libraries/KernelUtils.sol";
10: import {Actions, Keycode, Role, Permissions} from "@src/libraries/RentalStructs.sol";
11: import {Errors} from "@src/libraries/Errors.sol";
12: import {Events} from "src/libraries/Events.sol";
13: 
14: /////////////////////////////////////////////////////////////////////////////////
15: //                         Module Abstract Contracts                           //
16: /////////////////////////////////////////////////////////////////////////////////
17: 
18: /**
19:  * @title KernelAdapter
20:  * @notice A base contract to be inherited by both policies and modules. Provides common
21:  *         access to logic related to the kernel contract.
22:  */
23: abstract contract KernelAdapter {
24:     // The active kernel contract.
25:     Kernel public kernel;
26: 
27:     /**
28:      * @dev Instantiate this contract as a a kernel adapter. When using a proxy, the kernel address
29:      *      should be set to address(0).
30:      *
31:      * @param kernel_ Address of the kernel contract.
32:      */
33:     constructor(Kernel kernel_) {
34:         kernel = kernel_;
35:     }
36: 
37:     /**
38:      * @dev Modifier which only allows calls from the active kernel contract.
39:      */
40:     modifier onlyKernel() {
41:         if (msg.sender != address(kernel))
42:             revert Errors.KernelAdapter_OnlyKernel(msg.sender);
43:         _;
44:     }
45: 
46:     /**
47:      * @notice Points the adapter to reference a new kernel address. This function can
48:      *         only be called by the active kernel, and is used to perform migrations by
49:      *         telling all policies and modules where the new kernel is located before
50:      *         actually performing the migration.
51:      *
52:      * @param newKernel_  Address of the new kernel contract.
53:      */
54:     function changeKernel(Kernel newKernel_) external onlyKernel {
55:         kernel = newKernel_;
56:     }
57: }
58: 
59: /**
60:  * @title Module
61:  * @notice A base contract to be inherited by all module implementations. Provides common
62:  *         logic related to module functionality.
63:  */
64: abstract contract Module is KernelAdapter {
65:     /**
66:      * @dev Instantiate this contract as a a module. When using a proxy, the kernel address
67:      *      should be set to address(0).
68:      *
69:      * @param kernel_ Address of the kernel contract.
70:      */
71:     constructor(Kernel kernel_) KernelAdapter(kernel_) {}
72: 
73:     /**
74:      * @dev Modifier which only allows calls to the module if the policy contract making the
75:      *      call has been given explicit permission by the kernel first.
76:      */
77:     modifier permissioned() {
78:         if (!kernel.modulePermissions(KEYCODE(), Policy(msg.sender), msg.sig)) {
79:             revert Errors.Module_PolicyNotAuthorized(msg.sender);
80:         }
81:         _;
82:     }
83: 
84:     /**
85:      * @notice The 5-character keycode used to uniquely represent the module. This
86:      *         must be implemented by the inheriting contract.
87:      *
88:      * @return Keycode represented by the module.
89:      */
90:     function KEYCODE() public pure virtual returns (Keycode);
91: 
92:     /**
93:      * @notice Specifies the version of the module being implemented. Minor version
94:      *         changes retain the interface, and major version upgrades indicated
95:      *         breaking changes to the interface.
96:      *
97:      * @return major Major version of the module.
98:      * @return minor Minor version of the module.
99:      */
100:     function VERSION() external pure virtual returns (uint8 major, uint8 minor) {}
101: 
102:     /**
103:      * @notice Initialization function for the module which is called when the module is
104:      *         first installed or upgraded by the kernel. Can only be called by the kernel.
105:      */
106:     function INIT() external virtual onlyKernel {}
107: }
108: 
109: /**
110:  * @title Policy
111:  * @notice A base contract to be inherited by all policy implementations. Provides common
112:  *         logic related to policy functionality.
113:  */
114: abstract contract Policy is KernelAdapter {
115:     // Whether the policy is active or not.
116:     bool public isActive;
117: 
118:     /**
119:      * @dev Instantiate this contract as a a policy. When using a proxy, the kernel address
120:      *      should be set to address(0).
121:      *
122:      * @param kernel_ Address of the kernel contract.
123:      */
124:     constructor(Kernel kernel_) KernelAdapter(kernel_) {}
125: 
126:     /**
127:      * @dev Modifier which only allows calls from addresses which have explicitly been
128:      *      granted a role by the kernel.
129:      */
130:     modifier onlyRole(bytes32 role_) {
131:         Role role = toRole(role_);
132:         if (!kernel.hasRole(msg.sender, role)) {
133:             revert Errors.Policy_OnlyRole(role);
134:         }
135:         _;
136:     }
137: 
138:     /**
139:      * @notice When a policy is activated, it must respond with all of the module
140:      *         keycodes that it depends on. The kernel stores these dependencies as a
141:      *         mapping from module keycode to an array of policies that depend on it.
142:      *         This is useful because when a module is upgraded, it can know exactly
143:      *         the policies that depend upon it and call out to each policy to
144:      *         reconfigure its dependencies to use the upgraded module contract address.
145:      *
146:      * @param dependencies Keycodes of all the modules that the policy depends on.
147:      */
148:     function configureDependencies()
149:         external
150:         virtual
151:         onlyKernel
152:         returns (Keycode[] memory dependencies)
153:     {}
154: 
155:     /**
156:      * @notice When a policy is activated, it must respond with a series of
157:      *         keycode <> function selector pairs which represent a request for the
158:      *         policy to call a specific function selector at a specific module.
159:      *         These requests are stored as a mapping in the kernel while the policy
160:      *         is active, and the kernel will reject any call from a policy to a module
161:      *         which has not first requested permission.
162:      *
163:      * @param requests Keycode <> function selector pairs which define the module access
164:      *                 requested by a policy.
165:      */
166:     function requestPermissions()
167:         external
168:         view
169:         virtual
170:         onlyKernel
171:         returns (Permissions[] memory requests)
172:     {}
173: 
174:     /**
175:      * @dev Used by a policy to get the current address of a module
176:      *      at a specific keycode.
177:      *
178:      * @param keycode_ Keycode used to get the address of the module.
179:      */
180:     function getModuleAddress(Keycode keycode_) internal view returns (address) {
181:         address moduleForKeycode = address(kernel.getModuleForKeycode(keycode_));
182:         if (moduleForKeycode == address(0))
183:             revert Errors.Policy_ModuleDoesNotExist(keycode_);
184:         return moduleForKeycode;
185:     }
186: 
187:     /**
188:      * @notice Allows the kernel to grant or revoke the active status of the policy.
189:      *
190:      * @param activate_ Whether to activate or deactivate the policy.
191:      */
192:     function setActiveStatus(bool activate_) external onlyKernel {
193:         isActive = activate_;
194:     }
195: }
196: 
197: /////////////////////////////////////////////////////////////////////////////////
198: //                               Kernel Contract                               //
199: /////////////////////////////////////////////////////////////////////////////////
200: 
201: /**
202:  * @title Kernel
203:  * @notice A registry contract that manages a set of policy and module contracts, as well
204:  *         as the permissions to interact with those contracts.
205:  */
206: contract Kernel {
207:     // Admin addresses.
208:     address public executor;
209:     address public admin;
210: 
211:     // Module Management.
212:     Keycode[] public allKeycodes;
213:     mapping(Keycode => Module) public getModuleForKeycode; // get contract for module keycode.
214:     mapping(Module => Keycode) public getKeycodeForModule; // get module keycode for contract.
215: 
216:     // Module dependents data. Manages module dependencies for policies.
217:     mapping(Keycode => Policy[]) public moduleDependents;
218:     mapping(Keycode => mapping(Policy => uint256)) public getDependentIndex;
219: 
220:     // Module <> Policy Permissions. Keycode -> Policy -> Function Selector -> Permission.
221:     mapping(Keycode => mapping(Policy => mapping(bytes4 => bool)))
222:         public modulePermissions; // for policy addr, check if they have permission to call the function in the module.
223: 
224:     // List of all active policies.
225:     Policy[] public activePolicies;
226:     mapping(Policy => uint256) public getPolicyIndex;
227: 
228:     // Policy roles data.
229:     mapping(address => mapping(Role => bool)) public hasRole;
230:     mapping(Role => bool) public isRole;
231: 
232:     /////////////////////////////////////////////////////////////////////////////////
233:     //                                Constructor                                  //
234:     /////////////////////////////////////////////////////////////////////////////////
235: 
236:     /**
237:      * @dev Instantiate the kernel with executor and admin addresses.
238:      *
239:      * @param _executor Address in charge of handling kernel executions.
240:      * @param _admin    Address in charge of granting and revoking roles.
241:      */
242:     constructor(address _executor, address _admin) {
243:         executor = _executor;
244:         admin = _admin;
245:     }
246: 
247:     /////////////////////////////////////////////////////////////////////////////////
248:     //                                Modifiers                                    //
249:     /////////////////////////////////////////////////////////////////////////////////
250: 
251:     /**
252:      * @dev Modifier which only allows calls by an executing address.
253:      */
254:     modifier onlyExecutor() {
255:         if (msg.sender != executor) revert Errors.Kernel_OnlyExecutor(msg.sender);
256:         _;
257:     }
258: 
259:     /**
260:      * @dev modifier which only allows calls by an admin address.
261:      */
262:     modifier onlyAdmin() {
263:         if (msg.sender != admin) revert Errors.Kernel_OnlyAdmin(msg.sender);
264:         _;
265:     }
266: 
267:     /////////////////////////////////////////////////////////////////////////////////
268:     //                            External Functions                               //
269:     /////////////////////////////////////////////////////////////////////////////////
270: 
271:     /**
272:      * @dev Executes an action on a target address.
273:      *
274:      * @param action_ Action which will be performed.
275:      * @param target_ Address upon which the action will operate.
276:      */
277:     function executeAction(Actions action_, address target_) external onlyExecutor {
278:         if (action_ == Actions.InstallModule) {
279:             ensureContract(target_);
280:             ensureValidKeycode(Module(target_).KEYCODE());
281:             _installModule(Module(target_));
282:         } else if (action_ == Actions.UpgradeModule) {
283:             ensureContract(target_);
284:             ensureValidKeycode(Module(target_).KEYCODE());
285:             _upgradeModule(Module(target_));
286:         } else if (action_ == Actions.ActivatePolicy) {
287:             ensureContract(target_);
288:             _activatePolicy(Policy(target_));
289:         } else if (action_ == Actions.DeactivatePolicy) {
290:             ensureContract(target_);
291:             _deactivatePolicy(Policy(target_));
292:         } else if (action_ == Actions.MigrateKernel) {
293:             ensureContract(target_);
294:             _migrateKernel(Kernel(target_));
295:         } else if (action_ == Actions.ChangeExecutor) {
296:             executor = target_;
297:         } else if (action_ == Actions.ChangeAdmin) {
298:             admin = target_;
299:         }
300: 
301:         emit Events.ActionExecuted(action_, target_);
302:     }
303: 
304:     /**
305:      * @dev Grants a role to the target address.
306:      *
307:      * @param role_ Role to grant to the target.
308:      * @param addr_ Address that will receive the role.
309:      */
310:     function grantRole(Role role_, address addr_) public onlyAdmin {
311:         // Check that the address does not already have the role.
312:         if (hasRole[addr_][role_])
313:             revert Errors.Kernel_AddressAlreadyHasRole(addr_, role_);
314: 
315:         // Ensure the role is properly formatted.
316:         ensureValidRole(role_);
317: 
318:         // Mark this role as having been granted.
319:         if (!isRole[role_]) isRole[role_] = true;
320: 
321:         // Grant the role to the target.
322:         hasRole[addr_][role_] = true;
323: 
324:         emit Events.RoleGranted(role_, addr_);
325:     }
326: 
327:     /**
328:      * @dev Revokes a role from the target address.
329:      *
330:      * @param role_ Role to revoke from the target.
331:      * @param addr_ Address that will have the role removed.
332:      */
333:     function revokeRole(Role role_, address addr_) public onlyAdmin {
334:         // Check if the role has been granted before.
335:         if (!isRole[role_]) revert Errors.Kernel_RoleDoesNotExist(role_);
336: 
337:         // Check if the target address currently has the role.
338:         if (!hasRole[addr_][role_])
339:             revert Errors.Kernel_AddressDoesNotHaveRole(addr_, role_);
340: 
341:         // Revoke the role.
342:         hasRole[addr_][role_] = false;
343: 
344:         emit Events.RoleRevoked(role_, addr_);
345:     }
346: 
347:     /////////////////////////////////////////////////////////////////////////////////
348:     //                            Internal Functions                               //
349:     /////////////////////////////////////////////////////////////////////////////////
350: 
351:     /**
352:      * @dev Installs a new module into the kernel.
353:      *
354:      * @param newModule_ Address of the new module.
355:      */
356:     function _installModule(Module newModule_) internal {
357:         // Fetch the module keycode.
358:         Keycode keycode = newModule_.KEYCODE();
359: 
360:         // Make sure the keycode isnt in use already.
361:         if (address(getModuleForKeycode[keycode]) != address(0)) {
362:             revert Errors.Kernel_ModuleAlreadyInstalled(keycode);
363:         }
364: 
365:         // Connect the keycode to the module address.
366:         getModuleForKeycode[keycode] = newModule_;
367: 
368:         // Connect the module address to the keycode.
369:         getKeycodeForModule[newModule_] = keycode;
370: 
371:         // Keep a running array of all module keycodes.
372:         allKeycodes.push(keycode);
373: 
374:         // Initialize the module contract.
375:         newModule_.INIT();
376:     }
377: 
378:     /**
379:      * @dev Upgrades a module by changing the address that the keycode points to.
380:      *
381:      * @param newModule_ Address of the new module.
382:      */
383:     function _upgradeModule(Module newModule_) internal {
384:         // Get the keycode of the new module
385:         Keycode keycode = newModule_.KEYCODE();
386: 
387:         // Get the address of the old module
388:         Module oldModule = getModuleForKeycode[keycode];
389: 
390:         // Check that the old module contract exists, and that the old module
391:         // address is not the same as the new module
392:         if (address(oldModule) == address(0) || oldModule == newModule_) {
393:             revert Errors.Kernel_InvalidModuleUpgrade(keycode);
394:         }
395: 
396:         // The old module no longer points to the keycode.
397:         getKeycodeForModule[oldModule] = Keycode.wrap(bytes5(0));
398: 
399:         // The new module points to the keycode.
400:         getKeycodeForModule[newModule_] = keycode;
401: 
402:         // The keycode points to the new module.
403:         getModuleForKeycode[keycode] = newModule_;
404: 
405:         // Initialize the new module contract.
406:         newModule_.INIT();
407: 
408:         // Reconfigure policies so that all policies that depended on the old
409:         // module will refetch the new module address from the kernel.
410:         _reconfigurePolicies(keycode);
411:     }
412: 
413:     /**
414:      * @dev Activates a new policy into the kernel.
415:      *
416:      * @param policy_ Address of the policy to activate.
417:      */
418:     function _activatePolicy(Policy policy_) internal {
419:         // Ensure that the policy is not already active.
420:         if (policy_.isActive())
421:             revert Errors.Kernel_PolicyAlreadyApproved(address(policy_));
422: 
423:         // Grant permissions for policy to access restricted module functions.
424:         Permissions[] memory requests = policy_.requestPermissions();
425:         _setPolicyPermissions(policy_, requests, true);
426: 
427:         // Add policy to list of active policies.
428:         activePolicies.push(policy_);
429: 
430:         // Set the index of the policy in the array of active policies.
431:         getPolicyIndex[policy_] = activePolicies.length - 1;
432: 
433:         // Fetch module dependencies.
434:         Keycode[] memory dependencies = policy_.configureDependencies();
435:         uint256 depLength = dependencies.length;
436: 
437:         // Loop through each keycode the policy depends on.
438:         for (uint256 i; i < depLength; ++i) {
439:             Keycode keycode = dependencies[i];
440: 
441:             // Push the policy to the array of dependents for the keycode
442:             moduleDependents[keycode].push(policy_);
443: 
444:             // Set the index of the policy in the array of dependents.
445:             getDependentIndex[keycode][policy_] = moduleDependents[keycode].length - 1;
446:         }
447: 
448:         // Set policy status to active.
449:         policy_.setActiveStatus(true);
450:     }
451: 
452:     /**
453:      * @dev Deactivates an active policy from the kernel
454:      *
455:      * @param policy_ Address of the policy to deactivate.
456:      */
457:     function _deactivatePolicy(Policy policy_) internal {
458:         if (!policy_.isActive()) revert Errors.Kernel_PolicyNotApproved(address(policy_));
459: 
460:         // Fetch originally granted permissions from the policy
461:         // and then revoke them.
462:         Permissions[] memory requests = policy_.requestPermissions();
463:         _setPolicyPermissions(policy_, requests, false);
464: 
465:         // Get the index of the policy in the active policies array.
466:         uint256 idx = getPolicyIndex[policy_];
467: 
468:         // Get the index of the last policy in the active policy array.
469:         Policy lastPolicy = activePolicies[activePolicies.length - 1];
470: 
471:         // Set the last policy at the index of the policy to deactivate.
472:         activePolicies[idx] = lastPolicy;
473: 
474:         // Pop the last policy from the array.
475:         activePolicies.pop();
476: 
477:         // Set the last policy's index to the index of the policy
478:         // that was removed.
479:         getPolicyIndex[lastPolicy] = idx;
480: 
481:         // Delete the index of the policy being deactivated.
482:         delete getPolicyIndex[policy_];
483: 
484:         // Remove policy from array of dependents for each keycode
485:         // that the policy depends upon.
486:         _pruneFromDependents(policy_);
487: 
488:         // Set policy status to inactive.
489:         policy_.setActiveStatus(false);
490:     }
491: 
492:     /**
493:      * @dev Migrates the kernel to a new contract.
494:      *
495:      *      WARNING: THIS ACTION WILL BRICK THIS KERNEL.
496:      *
497:      *      By performing a migration, this kernel will no longer have any authority
498:      *      over the current policies and modules.
499:      *
500:      *      All functionality will move to the new kernel. The new kernel will need
501:      *      to add all of the modules and policies again via `executeAction`. Until
502:      *      all policies and modules are re-activated on the new kernel, policies will
503:      *      not be able to access permissioned functions on modules, and privileged
504:      *      addresses will not be able to access role-gated functions on policies.
505:      *
506:      * @param newKernel_ Address of the new kernel.
507:      */
508:     function _migrateKernel(Kernel newKernel_) internal {
509:         uint256 keycodeLen = allKeycodes.length;
510: 
511:         // For each keycode stored in the kernel.
512:         for (uint256 i; i < keycodeLen; ++i) {
513:             // get the module represented by the keycode.
514:             Module module = Module(getModuleForKeycode[allKeycodes[i]]);
515:             // Instruct the module to change the kernel.
516:             module.changeKernel(newKernel_);
517:         }
518: 
519:         // For each active policy stored in the kernel
520:         uint256 policiesLen = activePolicies.length;
521:         for (uint256 j; j < policiesLen; ++j) {
522:             // Get the policy.
523:             Policy policy = activePolicies[j];
524: 
525:             // Deactivate the policy before changing kernel.
526:             policy.setActiveStatus(false);
527: 
528:             // Instruct the policy to change the kernel.
529:             policy.changeKernel(newKernel_);
530:         }
531:     }
532: 
533:     /**
534:      * @dev All policies that are dependent on the module represented by the keycode
535:      *      must be reconfigured so that the policies can request the current
536:      *      address of the module from the kernel.
537:      *
538:      * @param keycode_ Keycode representing the module.
539:      */
540:     function _reconfigurePolicies(Keycode keycode_) internal {
541:         // Get an array of all policies that depend on the keycode.
542:         Policy[] memory dependents = moduleDependents[keycode_];
543:         uint256 depLength = dependents.length;
544: 
545:         // Loop through each policy.
546:         for (uint256 i; i < depLength; ++i) {
547:             // Reconfigure its dependencies.
548:             dependents[i].configureDependencies();
549:         }
550:     }
551: 
552:     /**
553:      * @dev Sets the permissions for a policy to interact with a module. Once the policy has
554:      *      been activated, these permissions do not change until the policy is deactivated.
555:      *
556:      * @param policy_   Address of the policy.
557:      * @param requests_ Permission requests comprised of keycode and function selector pairs.
558:      * @param grant_    Whether to grant these permissions or revoke them.
559:      */
560:     function _setPolicyPermissions(
561:         Policy policy_,
562:         Permissions[] memory requests_,
563:         bool grant_
564:     ) internal {
565:         uint256 reqLength = requests_.length;
566:         for (uint256 i = 0; i < reqLength; ++i) {
567:             // Set the permission for the keycode -> policy -> function selector.
568:             Permissions memory request = requests_[i];
569:             modulePermissions[request.keycode][policy_][request.funcSelector] = grant_;
570: 
571:             emit Events.PermissionsUpdated(
572:                 request.keycode,
573:                 policy_,
574:                 request.funcSelector,
575:                 grant_
576:             );
577:         }
578:     }
579: 
580:     /**
581:      * @dev All keycodes store an array of the policies that depend upon them,
582:      *      so a policy must be pruned from this array when it is deactivated.
583:      *
584:      * @param policy_ Address of the policy to prune from the dependency array.
585:      */
586:     function _pruneFromDependents(Policy policy_) internal {
587:         // Retrieve all keycodes that the policy is dependent upon.
588:         Keycode[] memory dependencies = policy_.configureDependencies();
589:         uint256 depcLength = dependencies.length;
590: 
591:         // Loop through each keycode.
592:         for (uint256 i; i < depcLength; ++i) {
593:             // Get the stored array of policies that depend on the keycode.
594:             Keycode keycode = dependencies[i];
595:             Policy[] storage dependents = moduleDependents[keycode];
596: 
597:             // Get the index of the policy to prune in the array.
598:             uint256 origIndex = getDependentIndex[keycode][policy_];
599: 
600:             // Get the address of the last policy in the array.
601:             Policy lastPolicy = dependents[dependents.length - 1];
602: 
603:             // Overwrite the last policy with the policy being pruned.
604:             dependents[origIndex] = lastPolicy;
605: 
606:             // Since the last policy exists twice now in the array, pop it
607:             // from the end of the array.
608:             dependents.pop();
609: 
610:             // Set the index of the swapped policy to its correct spot.
611:             getDependentIndex[keycode][lastPolicy] = origIndex;
612: 
613:             // Delete the index of the of the pruned policy.
614:             delete getDependentIndex[keycode][policy_];
615:         }
616:     }
617: }
618: 

```


*GitHub* : [1](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L1-L1)
### [N-50]<a name="n-50"></a> Contracts should have full test coverage
Attaining 100% code coverage is not an assurance of a bug-free codebase, but it significantly improves the likelihood of identifying simple bugs and aids in maintaining a stable codebase by preventing regressions during code modifications. Additionally, to achieve complete coverage, code writers usually have to structure their code more modularly, which implies testing each component independently. This reduces the complex interdependencies between modules and layers, creating a more understandable and auditable codebase. Consequently, this practice aids in enhancing code maintainability and reduces the risk of introducing bugs during future changes.

*There are 11 instance(s) of this issue:*

```solidity
23: contract PaymentEscrowBase  // <= FOUND

```


*GitHub* : [23](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L23-L23)

```solidity
37: contract PaymentEscrow is Proxiable, Module, PaymentEscrowBase  // <= FOUND

```


*GitHub* : [37](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L37-L37)

```solidity
14: contract StorageBase  // <= FOUND

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L14-L14)

```solidity
66: contract Storage is Proxiable, Module, StorageBase  // <= FOUND

```


*GitHub* : [66](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L66-L66)

```solidity
15: contract Admin is Policy  // <= FOUND

```


*GitHub* : [15](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L15-L15)

```solidity
41: contract Create is Policy, Signer, Zone, Accumulator  // <= FOUND

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L41-L41)

```solidity
22: contract Factory is Policy  // <= FOUND

```


*GitHub* : [22](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L22-L22)

```solidity
39: contract Guard is Policy, BaseGuard  // <= FOUND

```


*GitHub* : [39](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L39-L39)

```solidity
34: contract Stop is Policy, Signer, Reclaimer, Accumulator  // <= FOUND

```


*GitHub* : [34](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L34-L34)

```solidity
14: contract Create2Deployer  // <= FOUND

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L14-L14)

```solidity
206: contract Kernel  // <= FOUND

```


*GitHub* : [206](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L206-L206)
### [N-51]<a name="n-51"></a> Consider using named function calls
Named function calls in Solidity greatly improve code readability by explicitly mapping arguments to their respective parameter names. This clarity becomes critical when dealing with functions that have numerous or complex parameters, reducing potential errors due to misordered arguments. Therefore, adopting named function calls contributes to more maintainable and less error-prone code.

*There are 25 instance(s) of this issue:*

```solidity
175: 
176:         
177:         _safeTransfer(token, lender, lenderAmount); // <= FOUND

```


*GitHub* : [175](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L175-L177)

```solidity
178: 
179:         
180:         _safeTransfer(token, renter, renterAmount); // <= FOUND

```


*GitHub* : [178](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L178-L180)

```solidity
201: 
202:         
203:         _safeTransfer(token, settleToAddress, amount); // <= FOUND

```


*GitHub* : [201](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L201-L203)

```solidity
408: 
409:         
410:         _safeTransfer(token, to, skimmedBalance); // <= FOUND

```


*GitHub* : [408](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L408-L410)

```solidity
168:         
169:         (uint256 renterAmount, uint256 lenderAmount) = _calculatePaymentProRata( // <= FOUND
170:             amount, // <= FOUND
171:             elapsedTime, // <= FOUND
172:             totalTime
173:         );

```


*GitHub* : [168](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L168-L171)

```solidity
371: 
372:         
373:         _increaseDeposit(token, amount); // <= FOUND

```


*GitHub* : [371](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L371-L373)

```solidity
760: 
761:         
762:         address signer = _recoverSignerFromPayload( // <= FOUND
763:             _deriveRentPayloadHash(payload), // <= FOUND
764:             signature
765:         );

```


*GitHub* : [760](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L760-L763)

```solidity
322: 
323:         
324:         domainSeparator = _deriveDomainSeparator( // <= FOUND
325:             eip712DomainTypehash, // <= FOUND
326:             nameHash, // <= FOUND
327:             versionHash
328:         );

```


*GitHub* : [322](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L322-L326)

```solidity
46:         
47:         (
48:             _NAME_HASH, // <= FOUND
49:             _VERSION_HASH, // <= FOUND
50:             _EIP_712_DOMAIN_TYPEHASH, // <= FOUND
51:             _DOMAIN_SEPARATOR
52:         ) = _deriveTypehashes(); // <= FOUND

```


*GitHub* : [46](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L46-L52)

```solidity
54: 
55:         
56:         (
57:             _ITEM_TYPEHASH, // <= FOUND
58:             _HOOK_TYPEHASH, // <= FOUND
59:             _RENTAL_ORDER_TYPEHASH, // <= FOUND
60:             _ORDER_FULFILLMENT_TYPEHASH, // <= FOUND
61:             _ORDER_METADATA_TYPEHASH, // <= FOUND
62:             _RENT_PAYLOAD_TYPEHASH
63:         ) = _deriveRentalTypehashes(); // <= FOUND

```


*GitHub* : [54](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L54-L63)

```solidity
422:             
423:             _processBaseOrderOffer(items, offers, 0); // <= FOUND

```


*GitHub* : [422](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L422-L423)

```solidity
430:             
431:             _processPayOrderOffer(items, offers, 0); // <= FOUND

```


*GitHub* : [430](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L430-L431)

```solidity
771: 
772:         
773:         _rentFromZone(payload, seaportPayload); // <= FOUND

```


*GitHub* : [771](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L771-L773)

```solidity
700:                 _checkExpectedRecipient(execution, address(ESCRW)); // <= FOUND

```


*GitHub* : [700](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L700-L700)

```solidity
705:                 _checkExpectedRecipient(execution, expectedRentalSafe); // <= FOUND

```


*GitHub* : [705](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L705-L705)

```solidity
205:             
206:             uint256 tokenId = uint256(
207:                 _loadValueFromCalldata(data, e721_safe_transfer_from_1_token_id_offset) // <= FOUND
208:             );

```


*GitHub* : [205](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L205-L207)

```solidity
213:             
214:             uint256 tokenId = uint256(
215:                 _loadValueFromCalldata(data, e721_safe_transfer_from_2_token_id_offset) // <= FOUND
216:             );

```


*GitHub* : [213](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L213-L215)

```solidity
221:             
222:             uint256 tokenId = uint256(
223:                 _loadValueFromCalldata(data, e721_transfer_from_token_id_offset) // <= FOUND
224:             );

```


*GitHub* : [221](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L221-L223)

```solidity
229:             
230:             uint256 tokenId = uint256(
231:                 _loadValueFromCalldata(data, e721_approve_token_id_offset) // <= FOUND
232:             );

```


*GitHub* : [229](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L229-L231)

```solidity
237:             
238:             uint256 tokenId = uint256(
239:                 _loadValueFromCalldata(data, e1155_safe_transfer_from_token_id_offset) // <= FOUND
240:             );

```


*GitHub* : [237](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L237-L239)

```solidity
245:             
246:             address extension = address(
247:                 uint160(
248:                     uint256(
249:                         _loadValueFromCalldata(data, gnosis_safe_enable_module_offset) // <= FOUND
250:                     )
251:                 )
252:             );

```


*GitHub* : [245](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L245-L249)

```solidity
257:             
258:             address extension = address(
259:                 uint160(
260:                     uint256(
261:                         _loadValueFromCalldata(data, gnosis_safe_disable_module_offset) // <= FOUND
262:                     )
263:                 )
264:             );

```


*GitHub* : [257](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L257-L261)

```solidity
42: 
43:         
44:         address targetDeploymentAddress = getCreate2Address(salt, initCode); // <= FOUND

```


*GitHub* : [42](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L42-L44)

```solidity
425:         _setPolicyPermissions(policy_, requests, true); // <= FOUND

```


*GitHub* : [425](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L425-L425)

```solidity
463:         _setPolicyPermissions(policy_, requests, false); // <= FOUND

```


*GitHub* : [463](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L463-L463)
### [N-52]<a name="n-52"></a> Using XOR (^) and AND (&) bitwise equivalents
XOR (^) and AND (&) are bitwise operators that can be more efficient for specific operations in Solidity. XOR returns true if the bits being compared are different, and AND returns true if both bits are true. Using these operators can lead to more concise and efficient code for tasks such as toggling bits or checking specific bit conditions. By applying bitwise logic, you can reduce computational complexity and enhance code performance. Consider using XOR and AND where appropriate, understanding the specific requirements and ensuring that the use of these operators aligns with the intended logic of the application.

*There are 2 instance(s) of this issue:*

```solidity
100:     function _safeTransfer(address token, address to, uint256 value) internal { // <= FOUND
101:         
102:         (bool success, bytes memory data) = token.call(
103:             abi.encodeWithSelector(IERC20.transfer.selector, to, value)
104:         );
105: 
106:         
107:         
108:         
109:         
110:         
111:         
112:         
113:         
114:         
115:         if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
116:             revert Errors.PaymentEscrowModule_PaymentTransferFailed(token, to, value);
117:         }
118:     }

```


*GitHub* : [100](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L100-L100)

```solidity
215:     function _settlePayment(
216:         Item[] calldata items,
217:         OrderType orderType,
218:         address lender,
219:         address renter,
220:         uint256 start,
221:         uint256 end
222:     ) internal {
223:         
224:         uint256 elapsedTime = block.timestamp - start;
225:         uint256 totalTime = end - start;
226: 
227:         
228:         bool isRentalOver = elapsedTime >= totalTime;
229: 
230:         
231:         for (uint256 i = 0; i < items.length; ++i) {
232:             
233:             Item memory item = items[i];
234: 
235:             
236:             if (item.isERC20()) {
237:                 
238:                 
239:                 uint256 paymentAmount = item.amount;
240: 
241:                 
242:                 if (fee != 0) {
243:                     
244:                     uint256 paymentFee = _calculateFee(paymentAmount);
245: 
246:                     
247:                     paymentAmount -= paymentFee;
248:                 }
249: 
250:                 
251:                 
252:                 _decreaseDeposit(item.token, item.amount);
253: 
254:                 
255:                 if (orderType.isPayOrder() && !isRentalOver) {
256:                     
257:                     _settlePaymentProRata(
258:                         item.token,
259:                         paymentAmount,
260:                         lender,
261:                         renter,
262:                         elapsedTime,
263:                         totalTime
264:                     );
265:                 }
266:                 
267:                 else if (
268:                     (orderType.isPayOrder() && isRentalOver) || orderType.isBaseOrder()
269:                 ) {
270:                     
271:                     _settlePaymentInFull(
272:                         item.token,
273:                         paymentAmount,
274:                         item.settleTo,
275:                         lender,
276:                         renter
277:                     );
278:                 } else {
279:                     revert Errors.Shared_OrderTypeNotSupported(uint8(orderType));
280:                 }
281:             }
282:         }
283:     }

```


*GitHub* : [215](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L215-L215)
### [N-53]<a name="n-53"></a> Lack Of Brace Spacing
Lack of brace spacing in coding refers to the absence of spaces around braces, which can hinder code readability. In Solidity, as in many programming languages, spacing can enhance the visual distinction between different parts of the code, making it easier to follow. A lack of spacing can lead to a dense, confusing appearance. The resolution to this issue is to follow a consistent style guide that defines rules for brace spacing. By including spaces around braces, such as `{ statement }` instead of `{statement}`, developers can ensure that the code is more legible and maintainable, especially in larger codebases.

*There are 43 instance(s) of this issue:*

```solidity
4: 
5: import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L4-L5)

```solidity
4: 
5: import {Kernel, Module, Keycode} from "@src/Kernel.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L4-L5)

```solidity
5: import {Proxiable} from "@src/proxy/Proxiable.sol"; // <= FOUND

```


*GitHub* : [5](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L5-L5)

```solidity
4: import {Errors} from "@src/libraries/Errors.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L4-L4)

```solidity
13: import {Events} from "@src/libraries/Events.sol"; // <= FOUND

```


*GitHub* : [13](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L13-L13)

```solidity
6: import {RentalUtils} from "@src/libraries/RentalUtils.sol"; // <= FOUND

```


*GitHub* : [6](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L6-L6)

```solidity
7: import {RentalId, RentalAssetUpdate} from "@src/libraries/RentalStructs.sol"; // <= FOUND

```


*GitHub* : [7](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L7-L7)

```solidity
7: 
8: import {RentalId, RentalAssetUpdate} from "@src/libraries/RentalStructs.sol"; // <= FOUND

```


*GitHub* : [7](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L7-L8)

```solidity
4: 
5: import {IERC721} from "@openzeppelin-contracts/token/ERC721/IERC721.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L4-L5)

```solidity
5: import {IERC1155} from "@openzeppelin-contracts/token/ERC1155/IERC1155.sol"; // <= FOUND

```


*GitHub* : [5](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L5-L5)

```solidity
7: 
8: import {RentalOrder, Item, ItemType} from "@src/libraries/RentalStructs.sol"; // <= FOUND

```


*GitHub* : [7](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L7-L8)

```solidity
4: 
5: import {ECDSA} from "@openzeppelin-contracts/utils/cryptography/ECDSA.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L4-L5)

```solidity
10: 
11: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol"; // <= FOUND

```


*GitHub* : [10](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L10-L11)

```solidity
11: import {toKeycode} from "@src/libraries/KernelUtils.sol"; // <= FOUND

```


*GitHub* : [11](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L11-L11)

```solidity
14: import {Storage} from "@src/modules/Storage.sol"; // <= FOUND

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L14-L14)

```solidity
19: import {PaymentEscrow} from "@src/modules/PaymentEscrow.sol"; // <= FOUND

```


*GitHub* : [19](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L19-L19)

```solidity
4: 
5: import {ZoneParameters} from "@seaport-core/lib/rental/ConsiderationStructs.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L4-L5)

```solidity
5: import {ReceivedItem, SpentItem} from "@seaport-types/lib/ConsiderationStructs.sol"; // <= FOUND

```


*GitHub* : [5](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L5-L5)

```solidity
6: import {LibString} from "@solady/utils/LibString.sol"; // <= FOUND

```


*GitHub* : [6](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L6-L6)

```solidity
8: 
9: import {ISafe} from "@src/interfaces/ISafe.sol"; // <= FOUND

```


*GitHub* : [8](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L8-L9)

```solidity
9: import {IHook} from "@src/interfaces/IHook.sol"; // <= FOUND

```


*GitHub* : [9](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L9-L9)

```solidity
10: import {ZoneInterface} from "@src/interfaces/IZone.sol"; // <= FOUND

```


*GitHub* : [10](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L10-L10)

```solidity
13: import {toKeycode, toRole} from "@src/libraries/KernelUtils.sol"; // <= FOUND

```


*GitHub* : [13](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L13-L13)

```solidity
15: import {Signer} from "@src/packages/Signer.sol"; // <= FOUND

```


*GitHub* : [15](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L15-L15)

```solidity
16: import {Zone} from "@src/packages/Zone.sol"; // <= FOUND

```


*GitHub* : [16](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L16-L16)

```solidity
17: import {Accumulator} from "@src/packages/Accumulator.sol"; // <= FOUND

```


*GitHub* : [17](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L17-L17)

```solidity
496: 
497:             
498:             try
499:                 IHook(target).onStart( // <= FOUND
500:                     rentalWallet,
501:                     offer.token, // <= FOUND
502:                     offer.identifier, // <= FOUND
503:                     offer.amount, // <= FOUND
504:                     hooks[i].extraData // <= FOUND
505:                 )
506:             {} catch Error(string memory revertReason) { // <= FOUND

```


*GitHub* : [496](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L496-L506)

```solidity
4: 
5: import {SafeL2} from "@safe-contracts/SafeL2.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L4-L5)

```solidity
5: import {SafeProxyFactory} from "@safe-contracts/proxies/SafeProxyFactory.sol"; // <= FOUND

```


*GitHub* : [5](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L5-L5)

```solidity
6: import {TokenCallbackHandler} from "@safe-contracts/handler/TokenCallbackHandler.sol"; // <= FOUND

```


*GitHub* : [6](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L6-L6)

```solidity
15: import {Stop} from "@src/policies/Stop.sol"; // <= FOUND

```


*GitHub* : [15](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L15-L15)

```solidity
16: import {Guard} from "@src/policies/Guard.sol"; // <= FOUND

```


*GitHub* : [16](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L16-L16)

```solidity
4: 
5: import {BaseGuard} from "@safe-contracts/base/GuardManager.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L4-L5)

```solidity
4: import {Enum} from "@safe-contracts/common/Enum.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L4-L4)

```solidity
9: 
10: import {IHook} from "@src/interfaces/IHook.sol"; // <= FOUND

```


*GitHub* : [9](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L9-L10)

```solidity
10: import {Kernel, Policy, Permissions, Keycode} from "@src/Kernel.sol"; // <= FOUND

```


*GitHub* : [10](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L10-L10)

```solidity
167:         
168:         try IHook(hook).onTransaction(safe, to, value, data) {} catch Error( // <= FOUND

```


*GitHub* : [167](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L167-L168)

```solidity
4: 
5: import {Enum} from "@safe-contracts/common/Enum.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L4-L5)

```solidity
14: import {Reclaimer} from "@src/packages/Reclaimer.sol"; // <= FOUND

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L14-L14)

```solidity
226: 
227:             
228:             try
229:                 IHook(target).onStop( // <= FOUND
230:                     rentalWallet,
231:                     item.token, // <= FOUND
232:                     item.identifier, // <= FOUND
233:                     item.amount, // <= FOUND
234:                     hooks[i].extraData // <= FOUND
235:                 )
236:             {} catch Error(string memory revertReason) { // <= FOUND

```


*GitHub* : [226](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L226-L236)

```solidity
4: 
5: import {Errors} from "@src/libraries/Errors.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L4-L5)

```solidity
10: import {Actions, Keycode, Role, Permissions} from "@src/libraries/RentalStructs.sol"; // <= FOUND

```


*GitHub* : [10](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L10-L10)

```solidity
12: import {Events} from "src/libraries/Events.sol"; // <= FOUND

```


*GitHub* : [12](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L12-L12)
### [N-54]<a name="n-54"></a> Common functions should be refactored to a common base contract
In Solidity development, it's advisable to refactor common functions into a shared base contract to enhance code reusability and maintainability. This approach not only promotes clean and organized code but also saves on gas costs when deploying multiple contracts that utilize the same functions. By placing shared logic in a common base contract, it becomes easier to manage updates to those functions, reducing the likelihood of errors across multiple dependent contracts. The resolution is to identify the functions that are used across different contracts, encapsulate them in a base contract, and then inherit from that base contract wherever those functions are needed.

*There are 6 instance(s) of this issue:*

```solidity
86:     function MODULE_PROXY_INSTANTIATION(
87:         Kernel kernel_
88:     ) external onlyByProxy onlyUninitialized {
89:         kernel = kernel_;
90:         initialized = true;
91:     }

```


*GitHub* :

```solidity
96:     function VERSION() external pure override returns (uint8 major, uint8 minor) { // <= FOUND
97:         return (1, 0);
98:     }

```


*GitHub* : [96](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L96-L96)

```solidity
360:     function upgrade(address newImplementation) external onlyByProxy permissioned { // <= FOUND
361:         
362:         _upgrade(newImplementation);
363:     }

```


*GitHub* : [360](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L360-L360)

```solidity
369:     function freeze() external onlyByProxy permissioned { // <= FOUND
370:         
371:         _freeze();
372:     }

```


*GitHub* : [369](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L369-L369)

```solidity
72:     function configureDependencies()
73:         external
74:         override
75:         onlyKernel
76:         returns (Keycode[] memory dependencies)
77:     {
78:         dependencies = new Keycode[](2);
79: 
80:         dependencies[0] = toKeycode("STORE");
81:         STORE = Storage(getModuleAddress(toKeycode("STORE")));
82: 
83:         dependencies[1] = toKeycode("ESCRW");
84:         ESCRW = PaymentEscrow(getModuleAddress(toKeycode("ESCRW")));
85:     }

```


*GitHub* :

```solidity
73:     function configureDependencies()
74:         external
75:         override
76:         onlyKernel
77:         returns (Keycode[] memory dependencies)
78:     {
79:         dependencies = new Keycode[](1);
80: 
81:         dependencies[0] = toKeycode("STORE");
82:         STORE = Storage(getModuleAddress(toKeycode("STORE")));
83:     }

```


*GitHub* :
### [N-55]<a name="n-55"></a> Use of override is unnecessary
Starting with Solidity version 0.8.8, the use of the `override` keyword is simplified. If a function solely overrides an interface function and does not exist in multiple base contracts, specifying `override` becomes unnecessary. This change streamlines the code and makes it less verbose. Removing unnecessary use of `override` in these situations can make the code cleaner and more maintainable, aligning with the newer Solidity guidelines. It's a good practice to adapt to this updated behavior to stay consistent with the language's evolution and current best practices.

*There are 1 instance(s) of this issue:*

```solidity
353:     function checkAfterExecution(bytes32 txHash, bool success) external override  // <= FOUND

```


*GitHub* : [353](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L353-L353)
### [N-56]<a name="n-56"></a> If statement control structures do not comply with best practices
If statements which include a single line do not need to have curly brackets, however according to the Solidiity style guide the line of code executed upon the if statement condition being met should still be on the next line, not on the same line as the if statement declaration.

*There are 16 instance(s) of this issue:*

```solidity
296:         
297:         if (to.code.length == 0) revert Errors.StorageModule_NotContract(to); // <= FOUND

```


*GitHub* : [296](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L296-L297)

```solidity
299: 
300:         
301:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook); // <= FOUND

```


*GitHub* : [299](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L299-L301)

```solidity
299:         
300:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook); // <= FOUND

```


*GitHub* : [299](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L299-L300)

```solidity
321: 
322:         
323:         if (bitmap > uint8(7)) // <= FOUND
324:             revert Errors.StorageModule_InvalidHookStatusBitmap(bitmap); // <= FOUND

```


*GitHub* : [321](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L321-L324)

```solidity
94: 
95:             
96:             if (item.itemType == ItemType.ERC721) // <= FOUND
97:                 _transferERC721(item, rentalOrder.lender); // <= FOUND

```


*GitHub* : [94](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L94-L97)

```solidity
98: 
99:             
100:             if (item.itemType == ItemType.ERC1155) // <= FOUND
101:                 _transferERC1155(item, rentalOrder.lender); // <= FOUND

```


*GitHub* : [98](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L98-L101)

```solidity
41:         if (msg.sender != address(kernel)) // <= FOUND
42:             revert Errors.KernelAdapter_OnlyKernel(msg.sender); // <= FOUND

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L41-L42)

```solidity
182:         if (moduleForKeycode == address(0)) // <= FOUND
183:             revert Errors.Policy_ModuleDoesNotExist(keycode_); // <= FOUND

```


*GitHub* : [182](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L182-L183)

```solidity
255:         if (msg.sender != executor) revert Errors.Kernel_OnlyExecutor(msg.sender); // <= FOUND

```


*GitHub* : [255](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L255-L255)

```solidity
263:         if (msg.sender != admin) revert Errors.Kernel_OnlyAdmin(msg.sender); // <= FOUND

```


*GitHub* : [263](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L263-L263)

```solidity
312:         
313:         if (hasRole[addr_][role_]) // <= FOUND
314:             revert Errors.Kernel_AddressAlreadyHasRole(addr_, role_); // <= FOUND

```


*GitHub* : [312](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L312-L314)

```solidity
319: 
320:         
321:         if (!isRole[role_]) isRole[role_] = true; // <= FOUND

```


*GitHub* : [319](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L319-L321)

```solidity
335:         
336:         if (!isRole[role_]) revert Errors.Kernel_RoleDoesNotExist(role_); // <= FOUND

```


*GitHub* : [335](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L335-L336)

```solidity
338: 
339:         
340:         if (!hasRole[addr_][role_]) // <= FOUND
341:             revert Errors.Kernel_AddressDoesNotHaveRole(addr_, role_); // <= FOUND

```


*GitHub* : [338](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L338-L341)

```solidity
420:         
421:         if (policy_.isActive()) // <= FOUND
422:             revert Errors.Kernel_PolicyAlreadyApproved(address(policy_)); // <= FOUND

```


*GitHub* : [420](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L420-L422)

```solidity
458:         if (!policy_.isActive()) revert Errors.Kernel_PolicyNotApproved(address(policy_)); // <= FOUND

```


*GitHub* : [458](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L458-L458)
### [N-57]<a name="n-57"></a> Consider adding formal verification proofs

*There are 11 instance(s) of this issue:*

```solidity
23: contract PaymentEscrowBase  // <= FOUND

```


*GitHub* : [23](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L23-L23)

```solidity
37: contract PaymentEscrow is Proxiable, Module, PaymentEscrowBase  // <= FOUND

```


*GitHub* : [37](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L37-L37)

```solidity
14: contract StorageBase  // <= FOUND

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L14-L14)

```solidity
66: contract Storage is Proxiable, Module, StorageBase  // <= FOUND

```


*GitHub* : [66](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L66-L66)

```solidity
15: contract Admin is Policy  // <= FOUND

```


*GitHub* : [15](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L15-L15)

```solidity
41: contract Create is Policy, Signer, Zone, Accumulator  // <= FOUND

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L41-L41)

```solidity
22: contract Factory is Policy  // <= FOUND

```


*GitHub* : [22](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L22-L22)

```solidity
39: contract Guard is Policy, BaseGuard  // <= FOUND

```


*GitHub* : [39](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L39-L39)

```solidity
34: contract Stop is Policy, Signer, Reclaimer, Accumulator  // <= FOUND

```


*GitHub* : [34](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L34-L34)

```solidity
14: contract Create2Deployer  // <= FOUND

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L14-L14)

```solidity
206: contract Kernel  // <= FOUND

```


*GitHub* : [206](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L206-L206)
### [N-58]<a name="n-58"></a> Use string.concat() on strings instead of abi.encodePacked() for clearer semantic meaning
From Solidity 0.8.12 onwards, developers can utilize `string.concat()` to concatenate strings without additional padding. Opting for `string.concat()` over `abi.encodePacked()` offers clearer semantic interpretation of the code's intent, enhancing readability. This shift minimizes ambiguity, reducing the potential for misinterpretation by reviewers or future developers. Thus, for string concatenation tasks, it's recommended to transition to `string.concat()` for transparent, straightforward code that communicates its purpose distinctly.

*There are 4 instance(s) of this issue:*

```solidity
162:     function _deriveRentalOrderHash(
163:         RentalOrder memory order
164:     ) internal view returns (bytes32) {
165:         
166:         bytes32[] memory itemHashes = new bytes32[](order.items.length);
167:         bytes32[] memory hookHashes = new bytes32[](order.hooks.length);
168: 
169:         
170:         for (uint256 i = 0; i < order.items.length; ++i) {
171:             
172:             itemHashes[i] = _deriveItemHash(order.items[i]);
173:         }
174: 
175:         
176:         for (uint256 i = 0; i < order.hooks.length; ++i) {
177:             
178:             hookHashes[i] = _deriveHookHash(order.hooks[i]);
179:         }
180: 
181:         return
182:             keccak256(
183:                 abi.encode(
184:                     _RENTAL_ORDER_TYPEHASH,
185:                     order.seaportOrderHash,
186:                     keccak256(abi.encodePacked(itemHashes)),
187:                     keccak256(abi.encodePacked(hookHashes)),
188:                     order.orderType,
189:                     order.lender,
190:                     order.renter,
191:                     order.startTimestamp,
192:                     order.endTimestamp
193:                 )
194:             );
195:     }

```


*GitHub* : [162](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L162-L162)

```solidity
218:     function _deriveOrderMetadataHash(
219:         OrderMetadata memory metadata
220:     ) internal view returns (bytes32) {
221:         
222:         bytes32[] memory hookHashes = new bytes32[](metadata.hooks.length);
223: 
224:         
225:         for (uint256 i = 0; i < metadata.hooks.length; ++i) {
226:             
227:             hookHashes[i] = _deriveHookHash(metadata.hooks[i]);
228:         }
229: 
230:         
231:         return
232:             keccak256(
233:                 abi.encode(
234:                     _ORDER_METADATA_TYPEHASH,
235:                     metadata.rentDuration,
236:                     keccak256(abi.encodePacked(hookHashes))
237:                 )
238:             );
239:     }

```


*GitHub* : [218](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L218-L218)

```solidity
298:     function _deriveTypehashes()
299:         internal
300:         view
301:         returns (
302:             bytes32 nameHash,
303:             bytes32 versionHash,
304:             bytes32 eip712DomainTypehash,
305:             bytes32 domainSeparator
306:         )
307:     {
308:         
309:         nameHash = keccak256(bytes(_NAME));
310: 
311:         
312:         versionHash = keccak256(bytes(_VERSION));
313: 
314:         
315:         eip712DomainTypehash = keccak256(
316:             abi.encodePacked(
317:                 "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
318:             )
319:         );
320: 
321:         
322:         domainSeparator = _deriveDomainSeparator(
323:             eip712DomainTypehash,
324:             nameHash,
325:             versionHash
326:         );
327:     }

```


*GitHub* : [298](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L298-L298)

```solidity
339:     function _deriveRentalTypehashes()
340:         internal
341:         pure
342:         returns (
343:             bytes32 itemTypeHash,
344:             bytes32 hookTypeHash,
345:             bytes32 rentalOrderTypeHash,
346:             bytes32 orderFulfillmentTypeHash,
347:             bytes32 orderMetadataTypeHash,
348:             bytes32 rentPayloadTypeHash
349:         )
350:     {
351:         
352:         bytes memory itemTypeString = abi.encodePacked(
353:             "Item(uint8 itemType,uint8 settleTo,address token,uint256 amount,uint256 identifier)"
354:         );
355: 
356:         
357:         bytes memory hookTypeString = abi.encodePacked(
358:             "Hook(address target,uint256 itemIndex,bytes extraData)"
359:         );
360: 
361:         
362:         bytes memory rentalOrderTypeString = abi.encodePacked(
363:             "RentalOrder(bytes32 seaportOrderHash,Item[] items,Hook[] hooks,uint8 orderType,address lender,address renter,address rentalWallet,uint256 startTimestamp,uint256 endTimestamp)"
364:         );
365: 
366:         
367:         itemTypeHash = keccak256(itemTypeString);
368: 
369:         
370:         hookTypeHash = keccak256(hookTypeString);
371: 
372:         
373:         rentalOrderTypeHash = keccak256(
374:             abi.encode(rentalOrderTypeString, hookTypeString, itemTypeString)
375:         );
376: 
377:         {
378:             
379:             bytes memory orderFulfillmentTypeString = abi.encodePacked(
380:                 "OrderFulfillment(address recipient)"
381:             );
382: 
383:             
384:             bytes memory orderMetadataTypeString = abi.encodePacked(
385:                 "OrderMetadata(uint8 orderType,uint256 rentDuration,Hook[] hooks,bytes emittedExtraData)"
386:             );
387: 
388:             
389:             bytes memory rentPayloadTypeString = abi.encodePacked(
390:                 "RentPayload(OrderFulfillment fulfillment,OrderMetadata metadata,uint256 expiration,address intendedFulfiller)"
391:             );
392: 
393:             
394:             rentPayloadTypeHash = keccak256(
395:                 abi.encodePacked(
396:                     rentPayloadTypeString,
397:                     orderMetadataTypeString,
398:                     orderFulfillmentTypeString
399:                 )
400:             );
401: 
402:             
403:             orderFulfillmentTypeHash = keccak256(orderFulfillmentTypeString);
404: 
405:             
406:             orderMetadataTypeHash = keccak256(orderMetadataTypeString);
407:         }
408:     }

```


*GitHub* : [339](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L339-L339)
### [N-59]<a name="n-59"></a> function names should be lowerCamelCase

*There are 5 instance(s) of this issue:*

```solidity
86:     function MODULE_PROXY_INSTANTIATION(
87:         Kernel kernel_
88:     ) external onlyByProxy onlyUninitialized 

```


*GitHub* : [86](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L86-L86)

```solidity
96:     function VERSION() external pure override returns (uint8 major, uint8 minor) 

```


*GitHub* : [96](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L96-L96)

```solidity
103:     function KEYCODE() public pure override returns (Keycode) 

```


*GitHub* : [103](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L103-L103)

```solidity
100:     function VERSION() external pure virtual returns (uint8 major, uint8 minor) 

```


*GitHub* : [100](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L100-L100)

```solidity
106:     function INIT() external virtual onlyKernel 

```


*GitHub* : [106](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L106-L106)
### [N-60]<a name="n-60"></a> Consider bounding input array length
Unbounded array inputs in functions can lead to unintentional excessive gas consumption, potentially causing a transaction to revert after expending substantial gas. To enhance user experience and prevent such scenarios, consider implementing a `require()` statement that limits the array length to a defined maximum. This constraint ensures that transactions won't proceed if they're likely to hit gas limits due to array size, saving users from unnecessary gas costs and offering a more predictable interaction with the contract.

*There are 15 instance(s) of this issue:*

```solidity
231:        for (uint256 i = 0; i < items.length; ++i) { // <= FOUND
232:             
233:             Item memory item = items[i];
234: 
235:             
236:             if (item.isERC20()) {
237:                 
238:                 
239:                 uint256 paymentAmount = item.amount;
240: 
241:                 
242:                 if (fee != 0) {
243:                     
244:                     uint256 paymentFee = _calculateFee(paymentAmount);
245: 
246:                     
247:                     paymentAmount -= paymentFee;
248:                 }
249: 
250:                 
251:                 
252:                 _decreaseDeposit(item.token, item.amount);
253: 
254:                 
255:                 if (orderType.isPayOrder() && !isRentalOver) {
256:                     
257:                     _settlePaymentProRata(
258:                         item.token,
259:                         paymentAmount,
260:                         lender,
261:                         renter,
262:                         elapsedTime,
263:                         totalTime
264:                     );
265:                 }
266:                 
267:                 else if (
268:                     (orderType.isPayOrder() && isRentalOver) || orderType.isBaseOrder()
269:                 ) {
270:                     
271:                     _settlePaymentInFull(
272:                         item.token,
273:                         paymentAmount,
274:                         item.settleTo,
275:                         lender,
276:                         renter
277:                     );
278:                 } else {
279:                     revert Errors.Shared_OrderTypeNotSupported(uint8(orderType));
280:                 }

```


*GitHub* : [231](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L231-L231)

```solidity
341:        for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND
342:             
343:             _settlePayment(
344:                 orders[i].items,
345:                 orders[i].orderType,
346:                 orders[i].lender,
347:                 orders[i].renter,
348:                 orders[i].startTimestamp,
349:                 orders[i].endTimestamp
350:             );
351:         }

```


*GitHub* : [341](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L341-L341)

```solidity
197:        for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) { // <= FOUND
198:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
199: 
200:             
201:             rentedAssets[asset.rentalId] += asset.amount;
202:         }

```


*GitHub* : [197](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L197-L197)

```solidity
249:        for (uint256 i = 0; i < orderHashes.length; ++i) { // <= FOUND
250:             
251:             if (!orders[orderHashes[i]]) {
252:                 revert Errors.StorageModule_OrderDoesNotExist(orderHashes[i]);
253:             } else {
254:                 
255:                 delete orders[orderHashes[i]];
256:             }
257:         }

```


*GitHub* : [249](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L249-L249)

```solidity
170:        for (uint256 i = 0; i < order.items.length; ++i) { // <= FOUND
171:             
172:             itemHashes[i] = _deriveItemHash(order.items[i]);
173:         }

```


*GitHub* : [170](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L170-L170)

```solidity
225:        for (uint256 i = 0; i < metadata.hooks.length; ++i) { // <= FOUND
226:             
227:             hookHashes[i] = _deriveHookHash(metadata.hooks[i]);
228:         }

```


*GitHub* : [225](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L225-L225)

```solidity
261:        for (uint256 i; i < offers.length; ++i) { // <= FOUND
262:             
263:             SpentItem memory offer = offers[i];
264: 
265:             
266:             if (offer.isERC721()) {
267:                 
268:                 
269:                 itemType = ItemType.ERC721;
270:                 settleTo = SettleTo.LENDER;
271: 
272:                 
273:                 totalRentals++;
274:             }
275:             
276:             else if (offer.isERC1155()) {
277:                 
278:                 
279:                 itemType = ItemType.ERC1155;
280:                 settleTo = SettleTo.LENDER;
281: 
282:                 
283:                 totalRentals++;
284:             }
285:             
286:             else if (offer.isERC20()) {
287:                 
288:                 
289:                 itemType = ItemType.ERC20;
290:                 settleTo = SettleTo.RENTER;
291: 
292:                 
293:                 totalPayments++;
294:             }
295:             
296:             else {
297:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(offer.itemType);
298:             }
299: 
300:             
301:             rentalItems[i + startIndex] = Item({
302:                 itemType: itemType,
303:                 settleTo: settleTo,
304:                 token: offer.token,
305:                 amount: offer.amount,
306:                 identifier: offer.identifier
307:             });
308:         }

```


*GitHub* : [261](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L261-L261)

```solidity
375:        for (uint256 i; i < considerations.length; ++i) { // <= FOUND
376:             
377:             ReceivedItem memory consideration = considerations[i];
378: 
379:             
380:             if (consideration.isERC20()) {
381:                 totalPayments++;
382:             }
383:             
384:             else if (consideration.isRental()) {
385:                 totalRentals++;
386:             }
387:             
388:             else {
389:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
390:                     consideration.itemType
391:                 );
392:             }
393:         }

```


*GitHub* : [375](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L375-L375)

```solidity
475:        for (uint256 i = 0; i < hooks.length; ++i) { // <= FOUND
476:             
477:             target = hooks[i].target;
478: 
479:             
480:             if (!STORE.hookOnStart(target)) {
481:                 revert Errors.Shared_DisabledHook(target);
482:             }
483: 
484:             
485:             itemIndex = hooks[i].itemIndex;
486: 
487:             
488:             offer = offerItems[itemIndex];
489: 
490:             
491:             if (!offer.isRental()) {
492:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
493:             }
494: 
495:             
496:             try
497:                 IHook(target).onStart(
498:                     rentalWallet,
499:                     offer.token,
500:                     offer.identifier,
501:                     offer.amount,
502:                     hooks[i].extraData
503:                 )
504:             {} catch Error(string memory revertReason) {
505:                 
506:                 revert Errors.Shared_HookFailString(revertReason);
507:             } catch Panic(uint256 errorCode) {
508:                 
509:                 string memory stringErrorCode = LibString.toString(errorCode);
510: 
511:                 
512:                 revert Errors.Shared_HookFailString(
513:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
514:                 );
515:             } catch (bytes memory revertData) {
516:                 
517:                 revert Errors.Shared_HookFailBytes(revertData);
518:             }
519:         }

```


*GitHub* : [475](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L475-L475)

```solidity
695:        for (uint256 i = 0; i < executions.length; ++i) { // <= FOUND
696:             ReceivedItem memory execution = executions[i];
697: 
698:             
699:             if (execution.isERC20()) {
700:                 _checkExpectedRecipient(execution, address(ESCRW));
701:             }
702:             
703:             
704:             else if (execution.isRental()) {
705:                 _checkExpectedRecipient(execution, expectedRentalSafe);
706:             }
707:             
708:             else {
709:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(
710:                     execution.itemType
711:                 );
712:             }
713:         }

```


*GitHub* : [695](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L695-L695)

```solidity
205:        for (uint256 i = 0; i < hooks.length; ++i) { // <= FOUND
206:             
207:             target = hooks[i].target;
208: 
209:             
210:             if (!STORE.hookOnStop(target)) {
211:                 revert Errors.Shared_DisabledHook(target);
212:             }
213: 
214:             
215:             itemIndex = hooks[i].itemIndex;
216: 
217:             
218:             item = rentalItems[itemIndex];
219: 
220:             
221:             if (!item.isRental()) {
222:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
223:             }
224: 
225:             
226:             try
227:                 IHook(target).onStop(
228:                     rentalWallet,
229:                     item.token,
230:                     item.identifier,
231:                     item.amount,
232:                     hooks[i].extraData
233:                 )
234:             {} catch Error(string memory revertReason) {
235:                 
236:                 revert Errors.Shared_HookFailString(revertReason);
237:             } catch Panic(uint256 errorCode) {
238:                 
239:                 string memory stringErrorCode = LibString.toString(errorCode);
240: 
241:                 
242:                 revert Errors.Shared_HookFailString(
243:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
244:                 );
245:             } catch (bytes memory revertData) {
246:                 
247:                 revert Errors.Shared_HookFailBytes(revertData);
248:             }
249:         }

```


*GitHub* : [205](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L205-L205)

```solidity
276:        for (uint256 i; i < order.items.length; ++i) { // <= FOUND
277:             if (order.items[i].isRental()) {
278:                 
279:                 _insert(
280:                     rentalAssetUpdates,
281:                     order.items[i].toRentalId(order.rentalWallet),
282:                     order.items[i].amount
283:                 );
284:             }
285:         }

```


*GitHub* : [276](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L276-L276)

```solidity
324:        for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND
325:             
326:             _validateRentalCanBeStoped(
327:                 orders[i].orderType,
328:                 orders[i].endTimestamp,
329:                 orders[i].lender
330:             );
331: 
332:             
333:             for (uint256 j = 0; j < orders[i].items.length; ++j) { // <= FOUND
334:                 
335:                 if (orders[i].items[j].isRental()) {
336:                     _insert(
337:                         rentalAssetUpdates,
338:                         orders[i].items[j].toRentalId(orders[i].rentalWallet),
339:                         orders[i].items[j].amount
340:                     );
341:                 }
342:             }
343: 
344:             
345:             orderHashes[i] = _deriveRentalOrderHash(orders[i]);
346: 
347:             
348:             if (orders[i].hooks.length > 0) { // <= FOUND
349:                 _removeHooks(orders[i].hooks, orders[i].items, orders[i].rentalWallet);
350:             }
351: 
352:             
353:             _reclaimRentedItems(orders[i]);
354: 
355:             
356:             _emitRentalOrderStopped(orderHashes[i], msg.sender);
357:         }

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L324-L348)

```solidity
438:        for (uint256 i; i < depLength; ++i) {
439:             Keycode keycode = dependencies[i];
440: 
441:             
442:             moduleDependents[keycode].push(policy_);
443: 
444:             
445:             getDependentIndex[keycode][policy_] = moduleDependents[keycode].length - 1; // <= FOUND
446:         }

```


*GitHub* : [445](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L445-L445)

```solidity
592:        for (uint256 i; i < depcLength; ++i) {
593:             
594:             Keycode keycode = dependencies[i];
595:             Policy[] storage dependents = moduleDependents[keycode];
596: 
597:             
598:             uint256 origIndex = getDependentIndex[keycode][policy_];
599: 
600:             
601:             Policy lastPolicy = dependents[dependents.length - 1]; // <= FOUND
602: 
603:             
604:             dependents[origIndex] = lastPolicy;
605: 
606:             
607:             
608:             dependents.pop();
609: 
610:             
611:             getDependentIndex[keycode][lastPolicy] = origIndex;
612: 
613:             
614:             delete getDependentIndex[keycode][policy_];
615:         }

```


*GitHub* : [601](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L601-L601)
### [N-61]<a name="n-61"></a> Consider implementing EIP-5267 to securely describe EIP-712 domains being used
EIP-5267 aims to enhance EIP-712, which standardizes Ethereum's structured data signing. While EIP-712 defines how structured data should be signed, EIP-5267 focuses on standardizing the representation of domains. By doing so, it allows applications to fetch domain descriptions and dynamically construct domain separators, aiding in secure EIP-712 signature integration. To implement EIP-5267, contracts should expose a consistent method (e.g., `EIP712Domain()`) returning the domain's description. Adopting this ensures that applications can universally and securely handle EIP-712 signatures across various contracts, enhancing both security and scalability in Ethereum applications.

*There are 1 instance(s) of this issue:*

```solidity
315: 
316:         
317:         eip712DomainTypehash = keccak256( // <= FOUND
318:             abi.encodePacked(
319:                 "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)" // <= FOUND
320:             )
321:         );

```


*GitHub* : [315](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L315-L319)
### [N-62]<a name="n-62"></a> Add inline comments for unnamed variables in function declarations
Unnamed variables in function declarations can confuse developers. To enhance clarity, add inline comments next to each unnamed variable. E.g address, -> address /* to */,

*There are 1 instance(s) of this issue:*

```solidity
309:     function checkTransaction(
310:         address to,
311:         uint256 value,
312:         bytes memory data,
313:         Enum.Operation operation,
314:         uint256, // <= FOUND
315:         uint256, // <= FOUND
316:         uint256, // <= FOUND
317:         address, // <= FOUND
318:         address payable,
319:         bytes memory,
320:         address
321:     ) external override 

```


*GitHub* : [314](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L314-L317)
### [N-63]<a name="n-63"></a> Public state arrays should have a getter to return all elements
In Solidity, public state variables automatically generate a getter function. For non-array types, this is straightforward: it simply returns the value. However, for arrays, the automatically generated getter only allows retrieval of an element at a specific index, not the entire array. This is mainly to prevent unintentional high gas costs, as returning the entire array can be expensive if it's large. If developers want to retrieve the whole array, they must explicitly define a function, as auto-generation could inadvertently expose contracts to gas-related vulnerabilities or lead to unwanted behavior for larger arrays.

*There are 1 instance(s) of this issue:*

```solidity
206: contract Kernel {
207:     
208:     address public executor;
209:     address public admin;
210: 
212:     Keycode[] public allKeycodes; // <= FOUND
213:     mapping(Keycode => Module) public getModuleForKeycode; 
214:     mapping(Module => Keycode) public getKeycodeForModule; 
215: 
217:     mapping(Keycode => Policy[]) public moduleDependents;
218:     mapping(Keycode => mapping(Policy => uint256)) public getDependentIndex;
219: 
221:     mapping(Keycode => mapping(Policy => mapping(bytes4 => bool)))
222:         public modulePermissions; 
223: 
225:     Policy[] public activePolicies; // <= FOUND
226:     mapping(Policy => uint256) public getPolicyIndex;
227: 
229:     mapping(address => mapping(Role => bool)) public hasRole;
230:     mapping(Role => bool) public isRole;
231: 
362: }

```


*GitHub* : [206](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L206-L225)
### [N-64]<a name="n-64"></a> Ensure block.timestamp is only used in long time intervals
`block.timestamp` represents the current block's timestamp and can be influenced, within limits, by miners. For short time intervals, this malleability can be exploited, potentially allowing miners to manipulate contract behavior. For instance, they might fast-forward an expiration or delay an event. When designing smart contracts, if precise time checks are needed for short intervals, alternatives like block numbers can be considered. However, for longer durations where a few seconds of deviation is inconsequential, `block.timestamp` is generally safe and efficient. Always assess the implications of time manipulations for the specific use-case before utilizing `block.timestamp`. In practice, if you're using block.timestamp to measure intervals that are a matter of days, weeks, or longer, the potential manipulation by miners becomes less significant. Always prioritize the security and integrity of your smart contract operations when making these decisions.

*There are 1 instance(s) of this issue:*

```solidity
580:                 seaportOrderHash: seaportPayload.orderHash,
581:                 items: items,
582:                 hooks: payload.metadata.hooks,
583:                 orderType: payload.metadata.orderType,
584:                 lender: seaportPayload.offerer,
585:                 renter: payload.intendedFulfiller,
586:                 rentalWallet: payload.fulfillment.recipient,
587:                 startTimestamp: block.timestamp,
588:                 endTimestamp: block.timestamp + payload.metadata.rentDuration // <= FOUND
589:             });

```


*GitHub* : [580](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L580-L588)
### [N-65]<a name="n-65"></a> Don't use assembly for create2
Using assembly for create2 is error-prone and harder to read than higher-level Solidity. With the evolution of the Solidity language, a more abstracted and clear syntax for salted contract creation, which leverages the create2 opcode, has been introduced. Instead of manually managing assembly code, developers are encouraged to use the modern syntax, ensuring better readability, maintainability, and reduced chances of mistakes.

*There are 1 instance(s) of this issue:*

```solidity
53:         assembly {
54:             deploymentAddress := create2( // <= FOUND
55:                 
56:                 callvalue(),
57:                 
58:                 add(initCode, 0x20),
59:                 
60:                 mload(initCode),
61:                 
62:                 salt
63:             )
64:         }

```


*GitHub* : [54](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L54-L54)
### [N-66]<a name="n-66"></a> It is best practice to use linear inheritance
In Solidity, complex inheritance structures can obfuscate code understanding, introducing potential security risks. Multiple inheritance, especially with overlapping function names or state variables, can cause unintentional overrides or ambiguous behavior. Resolution: Strive for linear and simple inheritance chains. Avoid diamond or circular inheritance patterns. Clearly document the purpose and relationships of base contracts, ensuring that overrides are intentional. Tools like Remix or Hardhat can visualize inheritance chains, assisting in verification. Keeping inheritance streamlined aids in better code readability, reduces potential errors, and ensures smoother audits and upgrades.

*There are 5 instance(s) of this issue:*

```solidity
37: contract PaymentEscrow is Proxiable, Module, PaymentEscrowBase  // <= FOUND

```


*GitHub* : [37](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L37-L37)

```solidity
66: contract Storage is Proxiable, Module, StorageBase  // <= FOUND

```


*GitHub* : [66](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L66-L66)

```solidity
41: contract Create is Policy, Signer, Zone, Accumulator  // <= FOUND

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L41-L41)

```solidity
39: contract Guard is Policy, BaseGuard  // <= FOUND

```


*GitHub* : [39](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L39-L39)

```solidity
34: contract Stop is Policy, Signer, Reclaimer, Accumulator  // <= FOUND

```


*GitHub* : [34](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L34-L34)
### [N-67]<a name="n-67"></a> Contracts with only unimplemented functions can be labeled as abstract
In Solidity, a contract that's not meant to be deployed on its own but is intended to be inherited by other contracts should be marked `abstract`. This ensures that developers recognize the contract's incomplete or intended-to-be-extended nature. If a contract has unimplemented functions or is designed with the intention that another contract should extend its functionality, it should be explicitly labeled as `abstract`. This helps prevent inadvertent deployments and clearly communicates the contract's purpose to other developers. Resolution: Review the contract, and if it's not supposed to function standalone, mark it as `abstract` to make the intention clear.

*There are 3 instance(s) of this issue:*

```solidity
23: contract PaymentEscrowBase 

```


*GitHub* : [23](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L23-L23)

```solidity
14: contract StorageBase 

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L14-L14)

```solidity
14: contract Create2Deployer 

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L14-L14)
### [N-68]<a name="n-68"></a> A event should be emitted if a non immutable state variable is set in a constructor

*There are 2 instance(s) of this issue:*

```solidity
242:     constructor(address _executor, address _admin) {
243:         executor = _executor; // <= FOUND
244:         admin = _admin; // <= FOUND
245:     }

```


*GitHub* : [242](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L242-L244)

```solidity
33:     constructor(Kernel kernel_) {
34:         kernel = kernel_; // <= FOUND
35:     }

```


*GitHub* : [33](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L33-L34)
### [N-69]<a name="n-69"></a> Consider only defining one library/interface/contract per sol file
Combining multiple libraries, interfaces, or contracts in a single `.sol` file can lead to clutter, reduced readability, and versioning issues. **Resolution**: Adopt the best practice of defining only one library, interface, or contract per Solidity file. This modular approach enhances clarity, simplifies unit testing, and streamlines code review. Furthermore, segregating components makes version management easier, as updates to one component won't necessitate changes to a file housing multiple unrelated components. Structured file management can further assist in avoiding naming collisions and ensure smoother integration into larger systems or DApps.

*There are 3 instance(s) of this issue:*

```solidity
2: 
3: pragma solidity ^0.8.20;
4: 
5: import {Kernel, Module, Keycode} from "@src/Kernel.sol";
6: import {Proxiable} from "@src/proxy/Proxiable.sol";
7: import {RentalUtils} from "@src/libraries/RentalUtils.sol";
8: import {RentalId, RentalAssetUpdate} from "@src/libraries/RentalStructs.sol";
9: import {Errors} from "@src/libraries/Errors.sol";
10: 
15: contract StorageBase { // <= FOUND
16:     
21:     mapping(bytes32 orderHash => bool isActive) public orders;
22: 
27:     mapping(RentalId itemId => uint256 amount) public rentedAssets;
28: 
34:     mapping(address safe => uint256 nonce) public deployedSafes;
35: 
37:     uint256 public totalSafes;
38: 
45:     mapping(address to => address hook) internal _contractToHook;
46: 
48:     mapping(address hook => uint8 enabled) public hookStatus;
49: 
56:     mapping(address delegate => bool isWhitelisted) public whitelistedDelegates;
57: 
59:     mapping(address extension => bool isWhitelisted) public whitelistedExtensions;
60: }
61: 
67: contract Storage is Proxiable, Module, StorageBase { // <= FOUND
68:     using RentalUtils for address;
69: 
80:     constructor(Kernel kernel_) Module(kernel_) {}
81: 
87:     function MODULE_PROXY_INSTANTIATION(
88:         Kernel kernel_
89:     ) external onlyByProxy onlyUninitialized {
90:         kernel = kernel_;
91:         initialized = true;
92:     }
93: 
97:     function VERSION() external pure override returns (uint8 major, uint8 minor) {
98:         return (1, 0);
99:     }
100: 
104:     function KEYCODE() public pure override returns (Keycode) {
105:         return Keycode.wrap("STORE");
106:     }
107: 
119:     function isRentedOut(
120:         address recipient,
121:         address token,
122:         uint256 identifier
123:     ) external view returns (bool) {
124:         
125:         RentalId rentalId = RentalUtils.getItemPointer(recipient, token, identifier);
126: 
127:         
128:         return rentedAssets[rentalId] != 0;
129:     }
130: 
136:     function contractToHook(address to) external view returns (address) {
137:         
138:         address hook = _contractToHook[to];
139: 
140:         
141:         
142:         return hookStatus[hook] != 0 ? hook : address(0);
143:     }
144: 
150:     function hookOnTransaction(address hook) external view returns (bool) {
151:         
152:         return (uint8(1) & hookStatus[hook]) != 0;
153:     }
154: 
160:     function hookOnStart(address hook) external view returns (bool) {
161:         
162:         return uint8(2) & hookStatus[hook] != 0;
163:     }
164: 
170:     function hookOnStop(address hook) external view returns (bool) {
171:         
172:         return uint8(4) & hookStatus[hook] != 0;
173:     }
174: 
190:     function addRentals(
191:         bytes32 orderHash,
192:         RentalAssetUpdate[] memory rentalAssetUpdates
193:     ) external onlyByProxy permissioned {
194:         
195:         orders[orderHash] = true;
196: 
197:         
198:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {
199:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
200: 
201:             
202:             rentedAssets[asset.rentalId] += asset.amount;
203:         }
204:     }
205: 
217:     function removeRentals(
218:         bytes32 orderHash,
219:         RentalAssetUpdate[] calldata rentalAssetUpdates
220:     ) external onlyByProxy permissioned {
221:         
222:         if (!orders[orderHash]) {
223:             revert Errors.StorageModule_OrderDoesNotExist(orderHash);
224:         } else {
225:             
226:             delete orders[orderHash];
227:         }
228: 
229:         
230:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) {
231:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];

```


*GitHub* : [2](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L2-L67)

```solidity
2: 
3: pragma solidity ^0.8.20;
4: 
5: import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
6: 
7: import {Kernel, Module, Keycode} from "@src/Kernel.sol";
8: import {Proxiable} from "@src/proxy/Proxiable.sol";
9: import {
10:     RentalOrder,
11:     Item,
12:     ItemType,
13:     SettleTo,
14:     OrderType
15: } from "@src/libraries/RentalStructs.sol";
16: import {Errors} from "@src/libraries/Errors.sol";
17: import {Events} from "@src/libraries/Events.sol";
18: import {RentalUtils} from "@src/libraries/RentalUtils.sol";
19: 
24: contract PaymentEscrowBase { // <= FOUND
25:     
26:     mapping(address token => uint256 amount) public balanceOf;
27: 
29:     uint256 public fee;
30: }
31: 
38: contract PaymentEscrow is Proxiable, Module, PaymentEscrowBase { // <= FOUND
39:     using RentalUtils for Item;
40:     using RentalUtils for OrderType;
41: 
52:     constructor(Kernel kernel_) Module(kernel_) {}
53: 
59:     function MODULE_PROXY_INSTANTIATION(
60:         Kernel kernel_
61:     ) external onlyByProxy onlyUninitialized {
62:         kernel = kernel_;
63:         initialized = true;
64:     }
65: 
69:     function VERSION() external pure override returns (uint8 major, uint8 minor) {
70:         return (1, 0);
71:     }
72: 
76:     function KEYCODE() public pure override returns (Keycode) {
77:         return Keycode.wrap("ESCRW");
78:     }
79: 
89:     function _calculateFee(uint256 amount) internal view returns (uint256) {
90:         
91:         return (amount * fee) / 10000;
92:     }
93: 
101:     function _safeTransfer(address token, address to, uint256 value) internal {
102:         
103:         (bool success, bytes memory data) = token.call(
104:             abi.encodeWithSelector(IERC20.transfer.selector, to, value)
105:         );
106: 
107:         
108:         
109:         
110:         
111:         
112:         
113:         
114:         
115:         
116:         if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
117:             revert Errors.PaymentEscrowModule_PaymentTransferFailed(token, to, value);
118:         }
119:     }
120: 
133:     function _calculatePaymentProRata(
134:         uint256 amount,
135:         uint256 elapsedTime,
136:         uint256 totalTime
137:     ) internal pure returns (uint256 renterAmount, uint256 lenderAmount) {
138:         
139:         uint256 numerator = (amount * elapsedTime) * 1000;
140: 
141:         
142:         
143:         renterAmount = ((numerator / totalTime) + 500) / 1000;
144: 
145:         
146:         lenderAmount = amount - renterAmount;
147:     }

```


*GitHub* : [2](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L2-L38)

```solidity
2: 
3: pragma solidity ^0.8.20;
4: 
5: import {
6:     toRole,
7:     ensureContract,
8:     ensureValidKeycode,
9:     ensureValidRole
10: } from "@src/libraries/KernelUtils.sol";
11: import {Actions, Keycode, Role, Permissions} from "@src/libraries/RentalStructs.sol";
12: import {Errors} from "@src/libraries/Errors.sol";
13: import {Events} from "src/libraries/Events.sol";
14: 
24: abstract contract KernelAdapter { // <= FOUND
25:     
26:     Kernel public kernel;
27: 
34:     constructor(Kernel kernel_) {
35:         kernel = kernel_;
36:     }
37: 
41:     modifier onlyKernel() {
42:         if (msg.sender != address(kernel))
43:             revert Errors.KernelAdapter_OnlyKernel(msg.sender);
44:         _;
45:     }
46: 
55:     function changeKernel(Kernel newKernel_) external onlyKernel {
56:         kernel = newKernel_;
57:     }
58: }
59: 
65: abstract contract Module is KernelAdapter { // <= FOUND
66:     
72:     constructor(Kernel kernel_) KernelAdapter(kernel_) {}
73: 
78:     modifier permissioned() {
79:         if (!kernel.modulePermissions(KEYCODE(), Policy(msg.sender), msg.sig)) {
80:             revert Errors.Module_PolicyNotAuthorized(msg.sender);
81:         }
82:         _;
83:     }
84: 
91:     function KEYCODE() public pure virtual returns (Keycode);
92: 
101:     function VERSION() external pure virtual returns (uint8 major, uint8 minor) {}
102: 
107:     function INIT() external virtual onlyKernel {}
108: }
109: 
115: abstract contract Policy is KernelAdapter { // <= FOUND
116:     
117:     bool public isActive;
118: 
125:     constructor(Kernel kernel_) KernelAdapter(kernel_) {}
126: 
131:     modifier onlyRole(bytes32 role_) {
132:         Role role = toRole(role_);
133:         if (!kernel.hasRole(msg.sender, role)) {
134:             revert Errors.Policy_OnlyRole(role);
135:         }
136:         _;
137:     }
138: 
149:     function configureDependencies()
150:         external
151:         virtual
152:         onlyKernel
153:         returns (Keycode[] memory dependencies)
154:     {}
155: 
167:     function requestPermissions()
168:         external
169:         view
170:         virtual
171:         onlyKernel
172:         returns (Permissions[] memory requests)
173:     {}
174: 
181:     function getModuleAddress(Keycode keycode_) internal view returns (address) {
182:         address moduleForKeycode = address(kernel.getModuleForKeycode(keycode_));
183:         if (moduleForKeycode == address(0))
184:             revert Errors.Policy_ModuleDoesNotExist(keycode_);
185:         return moduleForKeycode;
186:     }
187: 
193:     function setActiveStatus(bool activate_) external onlyKernel {
194:         isActive = activate_;
195:     }
196: }
197: 
207: contract Kernel { // <= FOUND
208:     
209:     address public executor;
210:     address public admin;
211: 
213:     Keycode[] public allKeycodes;
214:     mapping(Keycode => Module) public getModuleForKeycode; 
215:     mapping(Module => Keycode) public getKeycodeForModule; 
216: 
218:     mapping(Keycode => Policy[]) public moduleDependents;
219:     mapping(Keycode => mapping(Policy => uint256)) public getDependentIndex;
220: 
222:     mapping(Keycode => mapping(Policy => mapping(bytes4 => bool)))
223:         public modulePermissions; 
224: 
226:     Policy[] public activePolicies;
227:     mapping(Policy => uint256) public getPolicyIndex;
228: 
230:     mapping(address => mapping(Role => bool)) public hasRole;
231:     mapping(Role => bool) public isRole;
232: 
243:     constructor(address _executor, address _admin) {
244:         executor = _executor;
245:         admin = _admin;
246:     }
247: 
255:     modifier onlyExecutor() {
256:         if (msg.sender != executor) revert Errors.Kernel_OnlyExecutor(msg.sender);
257:         _;
258:     }
259: 
263:     modifier onlyAdmin() {
264:         if (msg.sender != admin) revert Errors.Kernel_OnlyAdmin(msg.sender);
265:         _;
266:     }
267: 
278:     function executeAction(Actions action_, address target_) external onlyExecutor {
279:         if (action_ == Actions.InstallModule) {
280:             ensureContract(target_);
281:             ensureValidKeycode(Module(target_).KEYCODE());
282:             _installModule(Module(target_));
283:         } else if (action_ == Actions.UpgradeModule) {
284:             ensureContract(target_);
285:             ensureValidKeycode(Module(target_).KEYCODE());
286:             _upgradeModule(Module(target_));
287:         } else if (action_ == Actions.ActivatePolicy) {
288:             ensureContract(target_);
289:             _activatePolicy(Policy(target_));
290:         } else if (action_ == Actions.DeactivatePolicy) {
291:             ensureContract(target_);
292:             _deactivatePolicy(Policy(target_));
293:         } else if (action_ == Actions.MigrateKernel) {
294:             ensureContract(target_);
295:             _migrateKernel(Kernel(target_));
296:         } else if (action_ == Actions.ChangeExecutor) {
297:             executor = target_;
298:         } else if (action_ == Actions.ChangeAdmin) {
299:             admin = target_;
300:         }
301: 
302:         emit Events.ActionExecuted(action_, target_);
303:     }
304: 
311:     function grantRole(Role role_, address addr_) public onlyAdmin {
312:         
313:         if (hasRole[addr_][role_])
314:             revert Errors.Kernel_AddressAlreadyHasRole(addr_, role_);
315: 
316:         
317:         ensureValidRole(role_);
318: 
319:         
320:         if (!isRole[role_]) isRole[role_] = true;
321: 
322:         
323:         hasRole[addr_][role_] = true;
324: 
325:         emit Events.RoleGranted(role_, addr_);
326:     }
327: 
334:     function revokeRole(Role role_, address addr_) public onlyAdmin {
335:         
336:         if (!isRole[role_]) revert Errors.Kernel_RoleDoesNotExist(role_);
337: 
338:         
339:         if (!hasRole[addr_][role_])
340:             revert Errors.Kernel_AddressDoesNotHaveRole(addr_, role_);
341: 
342:         
343:         hasRole[addr_][role_] = false;
344: 
345:         emit Events.RoleRevoked(role_, addr_);
346:     }
347: 
357:     function _installModule(Module newModule_) internal {
358:         
359:         Keycode keycode = newModule_.KEYCODE();
360: 
361:         
362:         if (address(getModuleForKeycode[keycode]) != address(0)) {
363:             revert Errors.Kernel_ModuleAlreadyInstalled(keycode);
364:         }
365: 
366:         
367:         getModuleForKeycode[keycode] = newModule_;
368: 
369:         
370:         getKeycodeForModule[newModule_] = keycode;
371: 
372:         
373:         allKeycodes.push(keycode);
374: 
375:         
376:         newModule_.INIT();
377:     }
378: 
384:     function _upgradeModule(Module newModule_) internal {
385:         
386:         Keycode keycode = newModule_.KEYCODE();
387: 
388:         
389:         Module oldModule = getModuleForKeycode[keycode];
390: 
391:         
392:         
393:         if (address(oldModule) == address(0) || oldModule == newModule_) {
394:             revert Errors.Kernel_InvalidModuleUpgrade(keycode);
395:         }
396: 
397:         
398:         getKeycodeForModule[oldModule] = Keycode.wrap(bytes5(0));
399: 
400:         
401:         getKeycodeForModule[newModule_] = keycode;
402: 
403:         
404:         getModuleForKeycode[keycode] = newModule_;
405: 
406:         
407:         newModule_.INIT();
408: 
409:         
410:         
411:         _reconfigurePolicies(keycode);
412:     }
413: 
419:     function _activatePolicy(Policy policy_) internal {
420:         
421:         if (policy_.isActive())
422:             revert Errors.Kernel_PolicyAlreadyApproved(address(policy_));
423: 
424:         
425:         Permissions[] memory requests = policy_.requestPermissions();
426:         _setPolicyPermissions(policy_, requests, true);
427: 
428:         
429:         activePolicies.push(policy_);
430: 
431:         
432:         getPolicyIndex[policy_] = activePolicies.length - 1;
433: 
434:         
435:         Keycode[] memory dependencies = policy_.configureDependencies();
436:         uint256 depLength = dependencies.length;

```


*GitHub* : [2](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L2-L207)
### [N-70]<a name="n-70"></a> Immutable and constant integer state variables should not be casted
The definition of a constant or immutable variable is that they do not change, casting such variables can potentially push more than one 'value' to a constant, for example a uin128 constant can have its original value and that of when it's casted to uint64 (i.e it has some bytes truncated). This can create confusion and inconsistencies within the code which can inadvertently increase the attack surface of the project. It is thus advise to either change the uint byte size in the constant/immutable definition of the variable or introduce a second state variable to cover the differing casts that are expected such as having a uint128 constant and a separate uint64 constant.

*There are 1 instance(s) of this issue:*

```solidity
298:     function _deriveTypehashes()
299:         internal
300:         view
301:         returns (
302:             bytes32 nameHash,
303:             bytes32 versionHash,
304:             bytes32 eip712DomainTypehash,
305:             bytes32 domainSeparator
306:         )
307:     {
308:         
309:         nameHash = keccak256(bytes(_NAME)); // <= FOUND
310: 
311:         
312:         versionHash = keccak256(bytes(_VERSION)); // <= FOUND
313: 
314:         
315:         eip712DomainTypehash = keccak256(
316:             abi.encodePacked(
317:                 "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
318:             )
319:         );
320: 
321:         
322:         domainSeparator = _deriveDomainSeparator(
323:             eip712DomainTypehash,
324:             nameHash,
325:             versionHash
326:         );
327:     }

```


*GitHub* : [298](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L298-L312)
### [N-71]<a name="n-71"></a> Numbers downcast to addresses may result in collisions
Downcasting numbers to addresses in blockchain contracts, particularly in Ethereum's Solidity, involves risks such as possible address collisions. A collision occurs when different inputs, when cast or hashed, generate the same output address, potentially compromising contract integrity and asset security. If an uint256, for instance, is downcast to an address (effectively an uint160) without ensuring it’s a legitimate, collision-free conversion, different uint256 inputs might yield the same address, creating vulnerabilities attackers might exploit. Implementing thorough checks and opting for secure practices, like avoiding downcasting in critical logic or utilizing mappings with original uint256 as keys, mitigates risks

*There are 1 instance(s) of this issue:*

```solidity
94: 
95:         
96:         return address(uint160(uint256(addressHash))); // <= FOUND

```


*GitHub* : [96](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L96-L96)
### [N-72]<a name="n-72"></a> Public variable declarations should have NatSpec descriptions
Public variable declarations in smart contracts should ideally be accompanied by NatSpec comments to enhance code readability and provide clear documentation. NatSpec (Natural Language Specification) is a standard for writing comments in Ethereum smart contracts that can generate user-friendly documentation, improving the transparency of the contract's functionality. This is particularly crucial for public variables, as they are accessible externally, and understanding their role and impact is vital for both developers and users interacting with the contract

*There are 2 instance(s) of this issue:*

```solidity
35:     TokenCallbackHandler public immutable fallbackHandler; // <= FOUND
36:     SafeProxyFactory public immutable safeProxyFactory; // <= FOUND
37:     SafeL2 public immutable safeSingleton; // <= FOUND

```


*GitHub* : [35](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L35-L37)

```solidity
53:     Storage public STORE; // <= FOUND
54:     PaymentEscrow public ESCRW; // <= FOUND
55: 

```


*GitHub* : [53](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L53-L54)
### [N-73]<a name="n-73"></a> Use the Modern Upgradeable Contract Paradigm
Modern smart contract development often employs upgradeable contract structures, utilizing proxy patterns like OpenZeppelin’s Upgradeable Contracts. This paradigm separates logic and state, allowing developers to amend and enhance the contract's functionality without altering its state or the deployed contract address. Transitioning to this approach enhances long-term maintainability.

**Resolution**: Adopt a well-established proxy pattern for upgradeability, ensuring proper initialization and employing transparent proxies to mitigate potential risks. Embrace comprehensive testing and audit practices, particularly when updating contract logic, to ensure state consistency and security are preserved across upgrades. This ensures your contract remains robust and adaptable to future requirements.

*There are 11 instance(s) of this issue:*

```solidity
23: contract PaymentEscrowBase 

```


*GitHub* : [23](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L23-L23)

```solidity
37: contract PaymentEscrow is Proxiable, Module, PaymentEscrowBase 

```


*GitHub* : [37](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L37-L37)

```solidity
14: contract StorageBase 

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L14-L14)

```solidity
66: contract Storage is Proxiable, Module, StorageBase 

```


*GitHub* : [66](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L66-L66)

```solidity
15: contract Admin is Policy 

```


*GitHub* : [15](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L15-L15)

```solidity
41: contract Create is Policy, Signer, Zone, Accumulator 

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L41-L41)

```solidity
22: contract Factory is Policy 

```


*GitHub* : [22](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L22-L22)

```solidity
39: contract Guard is Policy, BaseGuard 

```


*GitHub* : [39](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L39-L39)

```solidity
34: contract Stop is Policy, Signer, Reclaimer, Accumulator 

```


*GitHub* : [34](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L34-L34)

```solidity
14: contract Create2Deployer 

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L14-L14)

```solidity
206: contract Kernel 

```


*GitHub* : [206](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L206-L206)
### [N-74]<a name="n-74"></a> Upgrade openzeppelin to the Latest Version - 5.0.0

*There are 4 instance(s) of this issue:*

```solidity
4: import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L4-L4)

```solidity
4: import {IERC721} from "@openzeppelin-contracts/token/ERC721/IERC721.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L4-L4)

```solidity
5: import {IERC1155} from "@openzeppelin-contracts/token/ERC1155/IERC1155.sol"; // <= FOUND

```


*GitHub* : [5](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L5-L5)

```solidity
4: import {ECDSA} from "@openzeppelin-contracts/utils/cryptography/ECDSA.sol"; // <= FOUND

```


*GitHub* : [4](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L4-L4)
### [N-75]<a name="n-75"></a> Use a struct to encapsulate multiple function parameters
Using a struct to encapsulate multiple parameters in Solidity functions can significantly enhance code readability and maintainability. Instead of passing a long list of arguments, which can be error-prone and hard to manage, a struct allows grouping related data into a single, coherent entity. This approach simplifies function signatures and makes the code more organized. It also enhances code clarity, as developers can easily understand the relationship between the parameters. Moreover, it aids in future code modifications and expansions, as adding or modifying a parameter only requires changes in the struct definition, rather than in every function that uses these parameters.

*There are 5 instance(s) of this issue:*

```solidity
159:     function _settlePaymentProRata(
160:         address token, // <= FOUND
161:         uint256 amount, // <= FOUND
162:         address lender, // <= FOUND
163:         address renter, // <= FOUND
164:         uint256 elapsedTime, // <= FOUND
165:         uint256 totalTime
166:     ) internal 

```


*GitHub* : [160](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L160-L164)

```solidity
190:     function _settlePaymentInFull(
191:         address token, // <= FOUND
192:         uint256 amount, // <= FOUND
193:         SettleTo settleTo, // <= FOUND
194:         address lender, // <= FOUND
195:         address renter
196:     ) internal 

```


*GitHub* : [191](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L191-L194)

```solidity
215:     function _settlePayment(
216:         Item[] calldata items, // <= FOUND
217:         OrderType orderType, // <= FOUND
218:         address lender, // <= FOUND
219:         address renter, // <= FOUND
220:         uint256 start, // <= FOUND
221:         uint256 end
222:     ) internal 

```


*GitHub* : [216](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L216-L220)

```solidity
159:     function _forwardToHook(
160:         address hook, // <= FOUND
161:         address safe, // <= FOUND
162:         address to, // <= FOUND
163:         uint256 value, // <= FOUND
164:         bytes memory data
165:     ) private 

```


*GitHub* : [160](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L160-L163)

```solidity
309:     function checkTransaction(
310:         address to, // <= FOUND
311:         uint256 value, // <= FOUND
312:         bytes memory data, // <= FOUND
313:         Enum.Operation operation, // <= FOUND
314:         uint256, // <= FOUND
315:         uint256, // <= FOUND
316:         uint256, // <= FOUND
317:         address, // <= FOUND
318:         address payable, // <= FOUND
319:         bytes memory, // <= FOUND
320:         address
321:     ) external override 

```


*GitHub* : [310](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L310-L319)
### [N-76]<a name="n-76"></a> Returning a struct instead of returning many variables is better
Returning a struct from a Solidity function instead of multiple variables offers several benefits, enhancing code clarity and efficiency. Structs allow for the grouping of related data into a single entity, making the function's return values more organized and easier to manage. This approach significantly improves readability, as it encapsulates the data logically, helping developers quickly understand the returned information's structure. Additionally, it simplifies function interfaces, reducing the potential for errors when handling multiple return values. By using structs, you can also easily extend or modify the returned data without altering the function signature, facilitating smoother updates and maintenance of your smart contract code.

*There are 1 instance(s) of this issue:*

```solidity
339:     function _deriveRentalTypehashes()
340:         internal
341:         pure
342:         returns (
343:             bytes32 itemTypeHash, // <= FOUND
344:             bytes32 hookTypeHash, // <= FOUND
345:             bytes32 rentalOrderTypeHash, // <= FOUND
346:             bytes32 orderFulfillmentTypeHash, // <= FOUND
347:             bytes32 orderMetadataTypeHash, // <= FOUND
348:             bytes32 rentPayloadTypeHash
349:         )
350:     

```


*GitHub* : [343](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L343-L347)
### [N-77]<a name="n-77"></a> Long numbers should include underscores to improve readability and prevent typos
A large number such as 2000000 is far more readable as 2_000_000, this will help prevent unintended bugs in the code

*There are 2 instance(s) of this issue:*

```solidity
90:         
91:         return (amount * fee) / 10000; // <= FOUND

```


*GitHub* : [91](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L91-L91)

```solidity
382:         
383:         if (feeNumerator > 10000) { // <= FOUND

```


*GitHub* : [383](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L383-L383)
### [N-78]<a name="n-78"></a> Consider using a format prettier or forge fmt
Some comments use // X and others //X Amend comments to use only use // X or //X consistently such style inconsistencies can be resolved by running the project through a format prettier or by using forge fmt.

*There are 1 instance(s) of this issue:*

```solidity
102: //github.com/martinetlee/create2-snippets#method-1-mixing-with-salt

```


*GitHub* : [102](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L102-L102)
### [N-79]<a name="n-79"></a> Avoid defining a function in a single line including it's contents

*There are 1 instance(s) of this issue:*

```solidity
90: 
97:     function KEYCODE() public pure virtual returns (Keycode); // <= FOUND

```


*GitHub* : [90](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L90-L97)
### [N-80]<a name="n-80"></a> Use 'using' keyword when using specific imports rather than calling the specific import directly
In Solidity, the `using` keyword can streamline the use of library functions for specific types. Instead of calling library functions directly with their full import paths, you can declare a library once with `using` for a specific type. This approach makes your code more readable and concise. For example, instead of `LibraryName.functionName(variable)`, you would first declare `using LibraryName for TypeName;` at the contract level. After this, you can call library functions directly on variables of `TypeName` like `variable.functionName()`. This method not only enhances code clarity but also promotes cleaner and more organized code, especially when multiple functions from the same library are used frequently.

*There are 99 instance(s) of this issue:*

```solidity
102:         
103:         (bool success, bytes memory data) = token.call(
104:             abi.encodeWithSelector(IERC20.transfer.selector, to, value) // <= FOUND 'IERC20.'
105:         );

```


*GitHub* : [102](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L102-L104)

```solidity
76:         return Keycode.wrap("ESCRW"); // <= FOUND 'Keycode.'

```


*GitHub* : [76](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L76-L76)

```solidity
104:         return Keycode.wrap("STORE"); // <= FOUND 'Keycode.'

```


*GitHub* : [104](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L104-L104)

```solidity
397: 
398:         
399:         getKeycodeForModule[oldModule] = Keycode.wrap(bytes5(0)); // <= FOUND 'Keycode.'

```


*GitHub* : [397](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L397-L399)

```solidity
116:             revert Errors.PaymentEscrowModule_PaymentTransferFailed(token, to, value); // <= FOUND 'Errors.'

```


*GitHub* : [116](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L116-L116)

```solidity
279:                     revert Errors.Shared_OrderTypeNotSupported(uint8(orderType)); // <= FOUND 'Errors.'

```


*GitHub* : [279](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L279-L279)

```solidity
367:             revert Errors.PaymentEscrow_ZeroPayment(); // <= FOUND 'Errors.'

```


*GitHub* : [367](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L367-L367)

```solidity
383:             revert Errors.PaymentEscrow_InvalidFeeNumerator(); // <= FOUND 'Errors.'

```


*GitHub* : [383](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L383-L383)

```solidity
222:             revert Errors.StorageModule_OrderDoesNotExist(orderHash); // <= FOUND 'Errors.'

```


*GitHub* : [222](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L222-L222)

```solidity
252:                 revert Errors.StorageModule_OrderDoesNotExist(orderHashes[i]); // <= FOUND 'Errors.'

```


*GitHub* : [252](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L252-L252)

```solidity
296:         
297:         if (to.code.length == 0) revert Errors.StorageModule_NotContract(to); // <= FOUND 'Errors.'

```


*GitHub* : [296](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L296-L297)

```solidity
299: 
300:         
301:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook); // <= FOUND 'Errors.'

```


*GitHub* : [299](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L299-L301)

```solidity
299:         
300:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook); // <= FOUND 'Errors.'

```


*GitHub* : [299](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L299-L300)

```solidity
321: 
322:         
323:         if (bitmap > uint8(7))
324:             revert Errors.StorageModule_InvalidHookStatusBitmap(bitmap); // <= FOUND 'Errors.'

```


*GitHub* : [321](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L321-L324)

```solidity
74:             revert Errors.ReclaimerPackage_OnlyDelegateCallAllowed(); // <= FOUND 'Errors.'

```


*GitHub* : [74](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L74-L74)

```solidity
81:             revert Errors.ReclaimerPackage_OnlyRentalSafeAllowed( // <= FOUND 'Errors.'
82:                 rentalOrder.rentalWallet
83:             );

```


*GitHub* : [81](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L81-L81)

```solidity
82:             revert Errors.SignerPackage_UnauthorizedFulfiller( // <= FOUND 'Errors.'
83:                 actualFulfiller,
84:                 intendedFulfiller
85:             );

```


*GitHub* : [82](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L82-L82)

```solidity
97:             revert Errors.SignerPackage_SignatureExpired(block.timestamp, expiration); // <= FOUND 'Errors.'

```


*GitHub* : [97](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L97-L97)

```solidity
202:             revert Errors.CreatePolicy_OfferCountZero(); // <= FOUND 'Errors.'

```


*GitHub* : [202](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L202-L202)

```solidity
223:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported(offer.itemType); // <= FOUND 'Errors.'

```


*GitHub* : [223](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L223-L223)

```solidity
312:             revert Errors.CreatePolicy_ItemCountZero(totalRentals, totalPayments); // <= FOUND 'Errors.'

```


*GitHub* : [312](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L312-L312)

```solidity
333:             revert Errors.CreatePolicy_ConsiderationCountZero(); // <= FOUND 'Errors.'

```


*GitHub* : [333](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L333-L333)

```solidity
343:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported( // <= FOUND 'Errors.'
344:                     consideration.itemType
345:                 );

```


*GitHub* : [343](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L343-L343)

```solidity
434:                 revert Errors.CreatePolicy_ConsiderationCountNonZero( // <= FOUND 'Errors.'
435:                     considerations.length
436:                 );

```


*GitHub* : [434](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L434-L434)

```solidity
443:                 revert Errors.CreatePolicy_OfferCountNonZero(offers.length); // <= FOUND 'Errors.'

```


*GitHub* : [443](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L443-L443)

```solidity
451:             revert Errors.Shared_OrderTypeNotSupported(uint8(orderType)); // <= FOUND 'Errors.'

```


*GitHub* : [451](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L451-L451)

```solidity
481:                 revert Errors.Shared_DisabledHook(target); // <= FOUND 'Errors.'

```


*GitHub* : [481](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L481-L481)

```solidity
492:                 revert Errors.Shared_NonRentalHookItem(itemIndex); // <= FOUND 'Errors.'

```


*GitHub* : [492](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L492-L492)

```solidity
506:                 
507:                 revert Errors.Shared_HookFailString(revertReason); // <= FOUND 'Errors.'

```


*GitHub* : [506](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L506-L507)

```solidity
512: 
513:                 
514:                 revert Errors.Shared_HookFailString( // <= FOUND 'Errors.'
515:                     string.concat("Hook reverted: Panic code ", stringErrorCode)
516:                 );

```


*GitHub* : [512](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L512-L514)

```solidity
517:                 
518:                 revert Errors.Shared_HookFailBytes(revertData); // <= FOUND 'Errors.'

```


*GitHub* : [517](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L517-L518)

```solidity
632:             revert Errors.CreatePolicy_RentDurationZero(); // <= FOUND 'Errors.'

```


*GitHub* : [632](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L632-L632)

```solidity
637:             revert Errors.CreatePolicy_InvalidOrderMetadataHash(); // <= FOUND 'Errors.'

```


*GitHub* : [637](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L637-L637)

```solidity
650:             revert Errors.CreatePolicy_InvalidRentalSafe(safe); // <= FOUND 'Errors.'

```


*GitHub* : [650](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L650-L650)

```solidity
655:             revert Errors.CreatePolicy_InvalidSafeOwner(owner, safe); // <= FOUND 'Errors.'

```


*GitHub* : [655](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L655-L655)

```solidity
671:             revert Errors.CreatePolicy_UnexpectedTokenRecipient( // <= FOUND 'Errors.'
672:                 execution.itemType,
673:                 execution.token,
674:                 execution.identifier,
675:                 execution.amount,
676:                 execution.recipient,
677:                 expectedRecipient
678:             );

```


*GitHub* : [671](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L671-L671)

```solidity
709:                 revert Errors.CreatePolicy_SeaportItemTypeNotSupported( // <= FOUND 'Errors.'
710:                     execution.itemType
711:                 );

```


*GitHub* : [709](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L709-L709)

```solidity
767:             revert Errors.CreatePolicy_UnauthorizedCreatePolicySigner(); // <= FOUND 'Errors.'

```


*GitHub* : [767](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L767-L767)

```solidity
144:             revert Errors.FactoryPolicy_InvalidSafeThreshold(threshold, owners.length); // <= FOUND 'Errors.'

```


*GitHub* : [144](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L144-L144)

```solidity
134:             revert Errors.GuardPolicy_UnauthorizedSelector(selector); // <= FOUND 'Errors.'

```


*GitHub* : [134](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L134-L134)

```solidity
146:             revert Errors.GuardPolicy_UnauthorizedExtension(extension); // <= FOUND 'Errors.'

```


*GitHub* : [146](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L146-L146)

```solidity
506:             
507:             revert Errors.Shared_HookFailString(revertReason); // <= FOUND 'Errors.'

```


*GitHub* : [506](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L506-L507)

```solidity
512: 
513:             
514:             revert Errors.Shared_HookFailString( // <= FOUND 'Errors.'
515:                 string.concat("Hook reverted: Panic code ", stringErrorCode)
516:             );

```


*GitHub* : [512](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L512-L514)

```solidity
517:             
518:             revert Errors.Shared_HookFailBytes(revertData); // <= FOUND 'Errors.'

```


*GitHub* : [517](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L517-L518)

```solidity
271:                 revert Errors.GuardPolicy_UnauthorizedSelector( // <= FOUND 'Errors.'
272:                     shared_set_approval_for_all_selector
273:                 );

```


*GitHub* : [271](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L271-L271)

```solidity
281:                 revert Errors.GuardPolicy_UnauthorizedSelector( // <= FOUND 'Errors.'
282:                     e1155_safe_batch_transfer_from_selector
283:                 );

```


*GitHub* : [281](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L281-L281)

```solidity
288:                 revert Errors.GuardPolicy_UnauthorizedSelector( // <= FOUND 'Errors.'
289:                     gnosis_safe_set_guard_selector
290:                 );

```


*GitHub* : [288](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L288-L288)

```solidity
325:             revert Errors.GuardPolicy_UnauthorizedDelegateCall(to); // <= FOUND 'Errors.'

```


*GitHub* : [325](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L325-L325)

```solidity
330:             revert Errors.GuardPolicy_FunctionSelectorRequired(); // <= FOUND 'Errors.'

```


*GitHub* : [330](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L330-L330)

```solidity
141:                 revert Errors.StopPolicy_CannotStopOrder(block.timestamp, msg.sender); // <= FOUND 'Errors.'

```


*GitHub* : [141](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L141-L141)

```solidity
181:             revert Errors.StopPolicy_ReclaimFailed(); // <= FOUND 'Errors.'

```


*GitHub* : [181](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L181-L181)

```solidity
38:             revert Errors.Create2Deployer_UnauthorizedSender(msg.sender, salt); // <= FOUND 'Errors.'

```


*GitHub* : [38](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L38-L38)

```solidity
46:             revert Errors.Create2Deployer_AlreadyDeployed(targetDeploymentAddress, salt); // <= FOUND 'Errors.'

```


*GitHub* : [46](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L46-L46)

```solidity
68:             revert Errors.Create2Deployer_MismatchedDeploymentAddress( // <= FOUND 'Errors.'
69:                 targetDeploymentAddress,
70:                 deploymentAddress
71:             );

```


*GitHub* : [68](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L68-L68)

```solidity
41:         if (msg.sender != address(kernel))
42:             revert Errors.KernelAdapter_OnlyKernel(msg.sender); // <= FOUND 'Errors.'

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L41-L42)

```solidity
79:             revert Errors.Module_PolicyNotAuthorized(msg.sender); // <= FOUND 'Errors.'

```


*GitHub* : [79](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L79-L79)

```solidity
133:             revert Errors.Policy_OnlyRole(role); // <= FOUND 'Errors.'

```


*GitHub* : [133](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L133-L133)

```solidity
182:         if (moduleForKeycode == address(0))
183:             revert Errors.Policy_ModuleDoesNotExist(keycode_); // <= FOUND 'Errors.'

```


*GitHub* : [182](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L182-L183)

```solidity
255:         if (msg.sender != executor) revert Errors.Kernel_OnlyExecutor(msg.sender); // <= FOUND 'Errors.'

```


*GitHub* : [255](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L255-L255)

```solidity
263:         if (msg.sender != admin) revert Errors.Kernel_OnlyAdmin(msg.sender); // <= FOUND 'Errors.'

```


*GitHub* : [263](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L263-L263)

```solidity
312:         
313:         if (hasRole[addr_][role_])
314:             revert Errors.Kernel_AddressAlreadyHasRole(addr_, role_); // <= FOUND 'Errors.'

```


*GitHub* : [312](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L312-L314)

```solidity
335:         
336:         if (!isRole[role_]) revert Errors.Kernel_RoleDoesNotExist(role_); // <= FOUND 'Errors.'

```


*GitHub* : [335](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L335-L336)

```solidity
338: 
339:         
340:         if (!hasRole[addr_][role_])
341:             revert Errors.Kernel_AddressDoesNotHaveRole(addr_, role_); // <= FOUND 'Errors.'

```


*GitHub* : [338](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L338-L341)

```solidity
362:             revert Errors.Kernel_ModuleAlreadyInstalled(keycode); // <= FOUND 'Errors.'

```


*GitHub* : [362](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L362-L362)

```solidity
393:             revert Errors.Kernel_InvalidModuleUpgrade(keycode); // <= FOUND 'Errors.'

```


*GitHub* : [393](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L393-L393)

```solidity
420:         
421:         if (policy_.isActive())
422:             revert Errors.Kernel_PolicyAlreadyApproved(address(policy_)); // <= FOUND 'Errors.'

```


*GitHub* : [420](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L420-L422)

```solidity
458:         if (!policy_.isActive()) revert Errors.Kernel_PolicyNotApproved(address(policy_)); // <= FOUND 'Errors.'

```


*GitHub* : [458](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L458-L458)

```solidity
411: 
412:         
413:         emit Events.FeeTaken(token, skimmedBalance); // <= FOUND 'Events.'

```


*GitHub* : [411](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L411-L413)

```solidity
171:         
172:         emit Events.RentalOrderStarted( // <= FOUND 'Events.'
173:             orderHash,
174:             extraData,
175:             order.seaportOrderHash,
176:             order.items,
177:             order.hooks,
178:             order.orderType,
179:             order.lender,
180:             order.renter,
181:             order.rentalWallet,
182:             order.startTimestamp,
183:             order.endTimestamp
184:         );

```


*GitHub* : [171](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L171-L172)

```solidity
192: 
193:         
194:         emit Events.RentalSafeDeployment(safe, owners, threshold); // <= FOUND 'Events.'

```


*GitHub* : [192](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L192-L194)

```solidity
113:         
114:         emit Events.RentalOrderStopped(seaportOrderHash, stopper); // <= FOUND 'Events.'

```


*GitHub* : [113](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L113-L114)

```solidity
301: 
302:         emit Events.ActionExecuted(action_, target_); // <= FOUND 'Events.'

```


*GitHub* : [301](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L301-L302)

```solidity
324: 
325:         emit Events.RoleGranted(role_, addr_); // <= FOUND 'Events.'

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L324-L325)

```solidity
344: 
345:         emit Events.RoleRevoked(role_, addr_); // <= FOUND 'Events.'

```


*GitHub* : [344](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L344-L345)

```solidity
571: 
572:             emit Events.PermissionsUpdated( // <= FOUND 'Events.'
573:                 request.keycode,
574:                 policy_,
575:                 request.funcSelector,
576:                 grant_
577:             );

```


*GitHub* : [571](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L571-L572)

```solidity
124:         
125:         RentalId rentalId = RentalUtils.getItemPointer(recipient, token, identifier); // <= FOUND 'RentalUtils.'

```


*GitHub* : [124](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L124-L125)

```solidity
38:         
39:         bytes32 _rentalId = RentalId.unwrap(rentalId); // <= FOUND 'RentalId.'

```


*GitHub* : [38](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L38-L39)

```solidity
168:         
169:         bool success = ISafe(order.rentalWallet).execTransactionFromModule(
170:             
171:             address(this),
172:             
173:             0,
174:             
175:             abi.encodeWithSelector(this.reclaimRentalOrder.selector, order), // <= FOUND 'RentalOrder.'
176:             
177:             Enum.Operation.DelegateCall // <= FOUND 'Enum.'
178:         );

```


*GitHub* : [168](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L168-L177)

```solidity
94: 
95:             
96:             if (item.itemType == ItemType.ERC721) // <= FOUND 'ItemType.'
97:                 _transferERC721(item, rentalOrder.lender);

```


*GitHub* : [94](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L94-L96)

```solidity
98: 
99:             
100:             if (item.itemType == ItemType.ERC1155) // <= FOUND 'ItemType.'
101:                 _transferERC1155(item, rentalOrder.lender);

```


*GitHub* : [98](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L98-L100)

```solidity
215:                 itemType = ItemType.ERC721; // <= FOUND 'ItemType.'

```


*GitHub* : [215](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L215-L215)

```solidity
219:                 itemType = ItemType.ERC1155; // <= FOUND 'ItemType.'

```


*GitHub* : [219](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L219-L219)

```solidity
215:                 
216:                 
217:                 itemType = ItemType.ERC721; // <= FOUND 'ItemType.'

```


*GitHub* : [215](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L215-L217)

```solidity
219:                 
220:                 
221:                 itemType = ItemType.ERC1155; // <= FOUND 'ItemType.'

```


*GitHub* : [219](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L219-L221)

```solidity
289:                 
290:                 
291:                 itemType = ItemType.ERC20; // <= FOUND 'ItemType.'

```


*GitHub* : [289](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L289-L291)

```solidity
351:                 itemType: ItemType.ERC20, // <= FOUND 'ItemType.'
352:                 settleTo: SettleTo.LENDER,
353:                 token: consideration.token,
354:                 amount: consideration.amount,
355:                 identifier: consideration.identifier
356:             });

```


*GitHub* : [351](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L351-L351)

```solidity
509:                 
510:                 string memory stringErrorCode = LibString.toString(errorCode); // <= FOUND 'LibString.'

```


*GitHub* : [509](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L509-L510)

```solidity
509:             
510:             string memory stringErrorCode = LibString.toString(errorCode); // <= FOUND 'LibString.'

```


*GitHub* : [509](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L509-L510)

```solidity
155: 
156:         
157:         bytes memory initializerPayload = abi.encodeCall(
158:             ISafe.setup, // <= FOUND 'ISafe.'
159:             (
160:                 
161:                 owners,
162:                 
163:                 threshold,
164:                 
165:                 address(this),
166:                 
167:                 data,
168:                 
169:                 address(fallbackHandler),
170:                 
171:                 address(0),
172:                 
173:                 0,
174:                 
175:                 payable(address(0))
176:             )
177:         );

```


*GitHub* : [155](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L155-L158)

```solidity
774: 
775:         
776:         validOrderMagicValue = ZoneInterface.validateOrder.selector; // <= FOUND 'ZoneInterface.'

```


*GitHub* : [774](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L774-L776)

```solidity
309: 
324:     function checkTransaction(
325:         address to,
326:         uint256 value,
327:         bytes memory data,
328:         Enum.Operation operation, // <= FOUND 'Enum.'
329:         uint256,
330:         uint256,
331:         uint256,
332:         address,
333:         address payable,
334:         bytes memory,
335:         address
336:     ) external override {

```


*GitHub* : [309](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L309-L328)

```solidity
324:         
325:         
326:         if (operation == Enum.Operation.DelegateCall && !STORE.whitelistedDelegates(to)) { // <= FOUND 'Enum.'

```


*GitHub* : [324](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L324-L326)

```solidity
278:         if (action_ == Actions.InstallModule) { // <= FOUND 'Actions.'

```


*GitHub* : [278](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L278-L278)

```solidity
282:         } else if (action_ == Actions.UpgradeModule) { // <= FOUND 'Actions.'

```


*GitHub* : [282](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L282-L282)

```solidity
286:         } else if (action_ == Actions.ActivatePolicy) { // <= FOUND 'Actions.'

```


*GitHub* : [286](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L286-L286)

```solidity
289:         } else if (action_ == Actions.DeactivatePolicy) { // <= FOUND 'Actions.'

```


*GitHub* : [289](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L289-L289)

```solidity
292:         } else if (action_ == Actions.MigrateKernel) { // <= FOUND 'Actions.'

```


*GitHub* : [292](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L292-L292)

```solidity
295:         } else if (action_ == Actions.ChangeExecutor) { // <= FOUND 'Actions.'

```


*GitHub* : [295](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L295-L295)

```solidity
297:         } else if (action_ == Actions.ChangeAdmin) { // <= FOUND 'Actions.'

```


*GitHub* : [297](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L297-L297)
### [N-81]<a name="n-81"></a> Try catch statement without human readable error
In Solidity, the `try-catch` statement is used for handling exceptions in external function calls and contract creation. However, when a `try-catch` block doesn't include a catch for specific human-readable errors (using `catch Error(string memory reason)`), it can miss catching exceptions that provide explanatory error messages. This lack of detailed error handling could hinder debugging and obscure the reasons behind transaction failures. To address this, it's recommended to include a catch block specifically for `Error` to capture and handle these descriptive error messages effectively. This practice enhances the contract's robustness by providing clearer insights into why certain operations fail, thereby improving maintainability and troubleshooting.

*There are 4 instance(s) of this issue:*

```solidity
507:             } catch Panic(uint256 errorCode) { // <= FOUND

```


*GitHub* : [507](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L507-L507)

```solidity
515:             } catch (bytes memory revertData) { // <= FOUND

```


*GitHub* : [515](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L515-L515)

```solidity
507:         } catch Panic(uint256 errorCode) { // <= FOUND

```


*GitHub* : [507](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L507-L507)

```solidity
515:         } catch (bytes memory revertData) { // <= FOUND

```


*GitHub* : [515](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L515-L515)
### [N-82]<a name="n-82"></a> Try catch statement with declared Error consumes more gas
Using a try-catch statement with a declared Error in Solidity can lead to increased gas consumption. This is because the contract must handle additional logic to catch specific error types, including human-readable error messages. When an Error is caught, the contract processes the string message associated with it, which adds to the gas cost due to the handling and storage of this string data.

*There are 3 instance(s) of this issue:*

```solidity
496: 
497:             
498:             try
499:                 IHook(target).onStart(
500:                     rentalWallet,
501:                     offer.token,
502:                     offer.identifier,
503:                     offer.amount,
504:                     hooks[i].extraData
505:                 )
506:             {} catch Error(string memory revertReason) { // <= FOUND

```


*GitHub* : [496](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L496-L506)

```solidity
167:         
168:         try IHook(hook).onTransaction(safe, to, value, data) {} catch Error( // <= FOUND

```


*GitHub* : [167](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L167-L168)

```solidity
226: 
227:             
228:             try
229:                 IHook(target).onStop(
230:                     rentalWallet,
231:                     item.token,
232:                     item.identifier,
233:                     item.amount,
234:                     hooks[i].extraData
235:                 )
236:             {} catch Error(string memory revertReason) { // <= FOUND

```


*GitHub* : [226](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L226-L236)
### [N-83]<a name="n-83"></a> Avoid declaring variables with the names of defined functions within the project
Having such variables can create confusion in both developers and in users of the project. Consider renaming these variables to improve code clarity.

*There are 2 instance(s) of this issue:*

```solidity
405: 
406:         
407:         uint256 skimmedBalance = trueBalance - syncedBalance; // <= FOUND

```


*GitHub* : [407](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L407-L407)

```solidity
32: 
44:     function deploy(
45:         bytes32 salt,
46:         bytes memory initCode
47:     ) external payable returns (address deploymentAddress) { // <= FOUND

```


*GitHub* : [47](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L47-L47)
### [N-84]<a name="n-84"></a> Reserved keyword 'error' used as a variable/object name
Since solidity version 0.8.4, 'error' has been reserved as a keyword and thus should not be used as a variable name.

*There are 2 instance(s) of this issue:*

```solidity
507:             } catch Panic(uint256 errorCode) { // <= FOUND

```


*GitHub* : [507](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L507-L507)

```solidity
507:         } catch Panic(uint256 errorCode) { // <= FOUND

```


*GitHub* : [507](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L507-L507)
### [N-85]<a name="n-85"></a> Avoid caching global vars used once within the function
If a cached variable is not used many times, it can be cheaper to call the global var directly.

*There are 1 instance(s) of this issue:*

```solidity
23:         original = address(this); // <= FOUND

```


*GitHub* : [23](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L23-L23)
### [N-86]<a name="n-86"></a> All verbatim blocks are considered identical by deduplicator and can incorrectly be unified
The Solidity Team reported a bug on October 24, 2023, affecting Yul code using the verbatim builtin, specifically in the Block Deduplicator optimizer step. This bug, present since Solidity version 0.8.5, caused incorrect deduplication of verbatim assembly items surrounded by identical opcodes, considering them identical regardless of their data. The bug was confined to pure Yul compilation with optimization enabled and was unlikely to be exploited as an attack vector. The conditions triggering the bug were very specific, and its occurrence was deemed to have a low likelihood. The bug was rated with an overall low score due to these factors.

*There are 1 instance(s) of this issue:*

```solidity
2: pragma solidity ^0.8.20; // <= FOUND

```


*GitHub* : [2](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L2-L2)
### [N-87]<a name="n-87"></a> ERC777 tokens can introduce reentrancy risks
ERC777 is an advanced token standard that introduces hooks, allowing operators to execute additional logic during transfers. While this feature offers greater flexibility, it also opens up the possibility of reentrancy attacks. Specifically, when tokens are sent, the receiving contract's `tokensReceived` hook gets called, and this external call can execute arbitrary code. An attacker can exploit this feature to re-enter the original function, potentially leading to double-spending or other types of financial manipulation.

To mitigate reentrancy risks with ERC777, it's crucial to adopt established security measures, such as utilizing reentrancy guards or following the check-effects-interactions pattern. Some developers opt to stick with the simpler ERC20 standard, which does not have these hooks, to minimize this risk. If you do choose to use ERC777, extreme caution and thorough auditing are advised to secure against potential reentrancy vulnerabilities.

*There are 2 instance(s) of this issue:*

```solidity
32:     function _transferERC721(Item memory item, address recipient) private { // <= FOUND
33:         IERC721(item.token).safeTransferFrom(address(this), recipient, item.identifier); // <= FOUND
34:     }

```


*GitHub* : [32](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L32-L33)

```solidity
42:     function _transferERC1155(Item memory item, address recipient) private { // <= FOUND
43:         IERC1155(item.token).safeTransferFrom(
44:             address(this),
45:             recipient,
46:             item.identifier,
47:             item.amount,
48:             ""
49:         );
50:     }

```


*GitHub* : [42](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L42-L42)
### [N-88]<a name="n-88"></a> Add inline comments for unnamed variables in function declarations
Unnamed variables in function declarations can confuse developers. To enhance clarity, add inline comments next to each unnamed variable. E.g address, -> address /* to */,

*There are 1 instance(s) of this issue:*

```solidity
309:     function checkTransaction(
310:         address to,
311:         uint256 value,
312:         bytes memory data,
313:         Enum.Operation operation,
314:         uint256, // <= FOUND
315:         uint256, // <= FOUND
316:         uint256, // <= FOUND
317:         address, // <= FOUND
318:         address payable,
319:         bytes memory,
320:         address
321:     ) external override 

```


*GitHub* : [314](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L314-L317)
### [N-89]<a name="n-89"></a> Public variable declarations should have NatSpec descriptions
Public variable declarations in smart contracts should ideally be accompanied by NatSpec comments to enhance code readability and provide clear documentation. NatSpec (Natural Language Specification) is a standard for writing comments in Ethereum smart contracts that can generate user-friendly documentation, improving the transparency of the contract's functionality. This is particularly crucial for public variables, as they are accessible externally, and understanding their role and impact is vital for both developers and users interacting with the contract

*There are 2 instance(s) of this issue:*

```solidity
35:     TokenCallbackHandler public immutable fallbackHandler; // <= FOUND
36:     SafeProxyFactory public immutable safeProxyFactory; // <= FOUND
37:     SafeL2 public immutable safeSingleton; // <= FOUND

```


*GitHub* : [35](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L35-L37)

```solidity
53:     Storage public STORE; // <= FOUND
54:     PaymentEscrow public ESCRW; // <= FOUND
55: 

```


*GitHub* : [53](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L53-L54)
### [N-90]<a name="n-90"></a> No @inheritdoc on override functions
In Solidity, using `@inheritdoc` on overridden functions is crucial for maintaining comprehensive and understandable NatSpec documentation. It ensures that when a function overrides an external interface or contract function, the original documentation is preserved. This not only helps developers understand the purpose and usage of the function but also aids in keeping documentation consistent and accurate across different versions of the codebase. Neglecting to use `@inheritdoc` can lead to incomplete or confusing documentation, making code maintenance and usage more challenging.

*There are 5 instance(s) of this issue:*

```solidity
96:     function VERSION() external pure override returns (uint8 major, uint8 minor)  // <= FOUND

```


*GitHub* : [96](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L96-L96)

```solidity
103:     function KEYCODE() public pure override returns (Keycode)  // <= FOUND

```


*GitHub* : [103](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L103-L103)

```solidity
733:     function validateOrder(
734:         ZoneParameters calldata zoneParams
735:     ) external override onlyRole("SEAPORT") returns (bytes4 validOrderMagicValue)  // <= FOUND

```


*GitHub* : [733](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L733-L735)

```solidity
309:     function checkTransaction(
310:         address to,
311:         uint256 value,
312:         bytes memory data,
313:         Enum.Operation operation,
314:         uint256,
315:         uint256,
316:         uint256,
317:         address,
318:         address payable,
319:         bytes memory,
320:         address
321:     ) external override  // <= FOUND

```


*GitHub* : [309](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L309-L321)

```solidity
353:     function checkAfterExecution(bytes32 txHash, bool success) external override  // <= FOUND

```


*GitHub* : [353](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L353-L353)
### [N-91]<a name="n-91"></a> Natspec @author is missing from contract

*There are 11 instance(s) of this issue:*

```solidity
23: contract PaymentEscrowBase 

```


*GitHub* : [23](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L23-L23)

```solidity
37: contract PaymentEscrow is Proxiable, Module, PaymentEscrowBase 

```


*GitHub* : [37](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L37-L37)

```solidity
14: contract StorageBase 

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L14-L14)

```solidity
66: contract Storage is Proxiable, Module, StorageBase 

```


*GitHub* : [66](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L66-L66)

```solidity
15: contract Admin is Policy 

```


*GitHub* : [15](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L15-L15)

```solidity
41: contract Create is Policy, Signer, Zone, Accumulator 

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L41-L41)

```solidity
22: contract Factory is Policy 

```


*GitHub* : [22](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L22-L22)

```solidity
39: contract Guard is Policy, BaseGuard 

```


*GitHub* : [39](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L39-L39)

```solidity
34: contract Stop is Policy, Signer, Reclaimer, Accumulator 

```


*GitHub* : [34](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L34-L34)

```solidity
14: contract Create2Deployer 

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L14-L14)

```solidity
206: contract Kernel 

```


*GitHub* : [206](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L206-L206)
### [N-92]<a name="n-92"></a> Natspec @dev is missing from contract

*There are 11 instance(s) of this issue:*

```solidity
23: contract PaymentEscrowBase 

```


*GitHub* : [23](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L23-L23)

```solidity
37: contract PaymentEscrow is Proxiable, Module, PaymentEscrowBase 

```


*GitHub* : [37](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L37-L37)

```solidity
14: contract StorageBase 

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L14-L14)

```solidity
66: contract Storage is Proxiable, Module, StorageBase 

```


*GitHub* : [66](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L66-L66)

```solidity
15: contract Admin is Policy 

```


*GitHub* : [15](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L15-L15)

```solidity
41: contract Create is Policy, Signer, Zone, Accumulator 

```


*GitHub* : [41](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L41-L41)

```solidity
22: contract Factory is Policy 

```


*GitHub* : [22](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L22-L22)

```solidity
39: contract Guard is Policy, BaseGuard 

```


*GitHub* : [39](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L39-L39)

```solidity
34: contract Stop is Policy, Signer, Reclaimer, Accumulator 

```


*GitHub* : [34](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L34-L34)

```solidity
14: contract Create2Deployer 

```


*GitHub* : [14](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L14-L14)

```solidity
206: contract Kernel 

```


*GitHub* : [206](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L206-L206)
### [N-93]<a name="n-93"></a> Natspec @author is missing from abstract

*There are 6 instance(s) of this issue:*

```solidity
12: abstract contract Accumulator 

```


*GitHub* : [12](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L12-L12)

```solidity
15: abstract contract Reclaimer 

```


*GitHub* : [15](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L15-L15)

```solidity
21: abstract contract Signer 

```


*GitHub* : [21](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L21-L21)

```solidity
23: abstract contract KernelAdapter 

```


*GitHub* : [23](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L23-L23)

```solidity
64: abstract contract Module is KernelAdapter 

```


*GitHub* : [64](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L64-L64)

```solidity
114: abstract contract Policy is KernelAdapter 

```


*GitHub* : [114](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L114-L114)
### [N-94]<a name="n-94"></a> Natspec @dev is missing from abstract

*There are 6 instance(s) of this issue:*

```solidity
12: abstract contract Accumulator 

```


*GitHub* : [12](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L12-L12)

```solidity
15: abstract contract Reclaimer 

```


*GitHub* : [15](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L15-L15)

```solidity
21: abstract contract Signer 

```


*GitHub* : [21](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L21-L21)

```solidity
23: abstract contract KernelAdapter 

```


*GitHub* : [23](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L23-L23)

```solidity
64: abstract contract Module is KernelAdapter 

```


*GitHub* : [64](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L64-L64)

```solidity
114: abstract contract Policy is KernelAdapter 

```


*GitHub* : [114](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L114-L114)
### [N-95]<a name="n-95"></a> Natspec @params comments are missing from modifier

*There are 1 instance(s) of this issue:*

```solidity
130:     modifier onlyRole(bytes32 role_) 

```


*GitHub* : [130](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L130-L130)
### [N-96]<a name="n-96"></a> Natspec @notice comments are missing from modifier

*There are 5 instance(s) of this issue:*

```solidity
40:     modifier onlyKernel() 

```


*GitHub* : [40](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L40-L40)

```solidity
77:     modifier permissioned() 

```


*GitHub* : [77](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L77-L77)

```solidity
130:     modifier onlyRole(bytes32 role_) 

```


*GitHub* : [130](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L130-L130)

```solidity
254:     modifier onlyExecutor() 

```


*GitHub* : [254](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L254-L254)

```solidity
262:     modifier onlyAdmin() 

```


*GitHub* : [262](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L262-L262)
### [N-97]<a name="n-97"></a> Natspec @dev comments are missing from function

*There are 56 instance(s) of this issue:*

```solidity
86:     function MODULE_PROXY_INSTANTIATION(
87:         Kernel kernel_
88:     ) external onlyByProxy onlyUninitialized 

```


*GitHub* : [86](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L86-L86)

```solidity
96:     function VERSION() external pure override returns (uint8 major, uint8 minor) 

```


*GitHub* : [96](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L96-L96)

```solidity
103:     function KEYCODE() public pure override returns (Keycode) 

```


*GitHub* : [103](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L103-L103)

```solidity
320:     function settlePayment(RentalOrder calldata order) external onlyByProxy permissioned 

```


*GitHub* : [320](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L320-L320)

```solidity
337:     function settlePaymentBatch(
338:         RentalOrder[] calldata orders
339:     ) external onlyByProxy permissioned 

```


*GitHub* : [337](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L337-L337)

```solidity
361:     function increaseDeposit(
362:         address token,
363:         uint256 amount
364:     ) external onlyByProxy permissioned 

```


*GitHub* : [361](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L361-L361)

```solidity
380:     function setFee(uint256 feeNumerator) external onlyByProxy permissioned 

```


*GitHub* : [380](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L380-L380)

```solidity
397:     function skim(address token, address to) external onlyByProxy permissioned 

```


*GitHub* : [397](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L397-L397)

```solidity
360:     function upgrade(address newImplementation) external onlyByProxy permissioned 

```


*GitHub* : [360](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L360-L360)

```solidity
369:     function freeze() external onlyByProxy permissioned 

```


*GitHub* : [369](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L369-L369)

```solidity
118:     function isRentedOut(
119:         address recipient,
120:         address token,
121:         uint256 identifier
122:     ) external view returns (bool) 

```


*GitHub* : [118](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L118-L118)

```solidity
135:     function contractToHook(address to) external view returns (address) 

```


*GitHub* : [135](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L135-L135)

```solidity
149:     function hookOnTransaction(address hook) external view returns (bool) 

```


*GitHub* : [149](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L149-L149)

```solidity
159:     function hookOnStart(address hook) external view returns (bool) 

```


*GitHub* : [159](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L159-L159)

```solidity
169:     function hookOnStop(address hook) external view returns (bool) 

```


*GitHub* : [169](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L169-L169)

```solidity
189:     function addRentals(
190:         bytes32 orderHash,
191:         RentalAssetUpdate[] memory rentalAssetUpdates
192:     ) external onlyByProxy permissioned 

```


*GitHub* : [189](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L189-L189)

```solidity
216:     function removeRentals(
217:         bytes32 orderHash,
218:         RentalAssetUpdate[] calldata rentalAssetUpdates
219:     ) external onlyByProxy permissioned 

```


*GitHub* : [216](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L216-L216)

```solidity
244:     function removeRentalsBatch(
245:         bytes32[] calldata orderHashes,
246:         RentalAssetUpdate[] calldata rentalAssetUpdates
247:     ) external onlyByProxy permissioned 

```


*GitHub* : [244](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L244-L244)

```solidity
274:     function addRentalSafe(address safe) external onlyByProxy permissioned 

```


*GitHub* : [274](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L274-L274)

```solidity
294:     function updateHookPath(address to, address hook) external onlyByProxy permissioned 

```


*GitHub* : [294](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L294-L294)

```solidity
313:     function updateHookStatus(
314:         address hook,
315:         uint8 bitmap
316:     ) external onlyByProxy permissioned 

```


*GitHub* : [313](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L313-L313)

```solidity
334:     function toggleWhitelistDelegate(
335:         address delegate,
336:         bool isEnabled
337:     ) external onlyByProxy permissioned 

```


*GitHub* : [334](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L334-L334)

```solidity
347:     function toggleWhitelistExtension(
348:         address extension,
349:         bool isEnabled
350:     ) external onlyByProxy permissioned 

```


*GitHub* : [347](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L347-L347)

```solidity
71:     function reclaimRentalOrder(RentalOrder calldata rentalOrder) external 

```


*GitHub* : [71](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L71-L71)

```solidity
73:     function configureDependencies()
74:         external
75:         override
76:         onlyKernel
77:         returns (Keycode[] memory dependencies)
78:     

```


*GitHub* : [73](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L73-L73)

```solidity
94:     function requestPermissions()
95:         external
96:         view
97:         override
98:         onlyKernel
99:         returns (Permissions[] memory requests)
100:     

```


*GitHub* : [94](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L94-L94)

```solidity
99:     function toggleWhitelistDelegate(
100:         address delegate,
101:         bool isEnabled
102:     ) external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [99](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L99-L99)

```solidity
113:     function toggleWhitelistExtension(
114:         address extension,
115:         bool isEnabled
116:     ) external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [113](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L113-L113)

```solidity
126:     function upgradeStorage(address newImplementation) external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [126](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L126-L126)

```solidity
134:     function freezeStorage() external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [134](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L134-L134)

```solidity
144:     function upgradePaymentEscrow(
145:         address newImplementation
146:     ) external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [144](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L144-L144)

```solidity
154:     function freezePaymentEscrow() external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [154](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L154-L154)

```solidity
164:     function skim(address token, address to) external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [164](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L164-L164)

```solidity
173:     function setFee(uint256 feeNumerator) external onlyRole("ADMIN_ADMIN") 

```


*GitHub* : [173](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Admin.sol#L173-L173)

```solidity
117:     function domainSeparator() external view returns (bytes32) 

```


*GitHub* : [117](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L117-L117)

```solidity
126:     function getRentalOrderHash(
127:         RentalOrder memory order
128:     ) external view returns (bytes32) 

```


*GitHub* : [126](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L126-L126)

```solidity
137:     function getRentPayloadHash(
138:         RentPayload memory payload
139:     ) external view returns (bytes32) 

```


*GitHub* : [137](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L137-L137)

```solidity
148:     function getOrderMetadataHash(
149:         OrderMetadata memory metadata
150:     ) external view returns (bytes32) 

```


*GitHub* : [148](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L148-L148)

```solidity
733:     function validateOrder(
734:         ZoneParameters calldata zoneParams
735:     ) external override onlyRole("SEAPORT") returns (bytes4 validOrderMagicValue) 

```


*GitHub* : [733](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L733-L733)

```solidity
122:     function initializeRentalSafe(address _stopPolicy, address _guardPolicy) external 

```


*GitHub* : [122](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L122-L122)

```solidity
138:     function deployRentalSafe(
139:         address[] calldata owners,
140:         uint256 threshold
141:     ) external returns (address safe) 

```


*GitHub* : [138](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L138-L138)

```solidity
309:     function checkTransaction(
310:         address to,
311:         uint256 value,
312:         bytes memory data,
313:         Enum.Operation operation,
314:         uint256,
315:         uint256,
316:         uint256,
317:         address,
318:         address payable,
319:         bytes memory,
320:         address
321:     ) external override 

```


*GitHub* : [309](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L309-L309)

```solidity
353:     function checkAfterExecution(bytes32 txHash, bool success) external override 

```


*GitHub* : [353](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L353-L353)

```solidity
362:     function updateHookPath(address to, address hook) external onlyRole("GUARD_ADMIN") 

```


*GitHub* : [362](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L362-L362)

```solidity
373:     function updateHookStatus(
374:         address hook,
375:         uint8 bitmap
376:     ) external onlyRole("GUARD_ADMIN") 

```


*GitHub* : [373](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L373-L373)

```solidity
265:     function stopRent(RentalOrder calldata order) external 

```


*GitHub* : [265](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L265-L265)

```solidity
313:     function stopRentBatch(RentalOrder[] calldata orders) external 

```


*GitHub* : [313](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L313-L313)

```solidity
32:     function deploy(
33:         bytes32 salt,
34:         bytes memory initCode
35:     ) external payable returns (address deploymentAddress) 

```


*GitHub* : [32](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L32-L32)

```solidity
84:     function getCreate2Address(
85:         bytes32 salt,
86:         bytes memory initCode
87:     ) public view returns (address) 

```


*GitHub* : [84](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L84-L84)

```solidity
107:     function generateSaltWithSender(
108:         address sender,
109:         bytes12 data
110:     ) public pure returns (bytes32 salt) 

```


*GitHub* : [107](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L107-L107)

```solidity
54:     function changeKernel(Kernel newKernel_) external onlyKernel 

```


*GitHub* : [54](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L54-L54)

```solidity
100:     function VERSION() external pure virtual returns (uint8 major, uint8 minor) 

```


*GitHub* : [100](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L100-L100)

```solidity
106:     function INIT() external virtual onlyKernel 

```


*GitHub* : [106](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L106-L106)

```solidity
148:     function configureDependencies()
149:         external
150:         virtual
151:         onlyKernel
152:         returns (Keycode[] memory dependencies)
153:     

```


*GitHub* : [148](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L148-L148)

```solidity
166:     function requestPermissions()
167:         external
168:         view
169:         virtual
170:         onlyKernel
171:         returns (Permissions[] memory requests)
172:     

```


*GitHub* : [166](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L166-L166)

```solidity
192:     function setActiveStatus(bool activate_) external onlyKernel 

```


*GitHub* : [192](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L192-L192)
### [N-98]<a name="n-98"></a> Natspec @notice comments are missing from function

*There are 57 instance(s) of this issue:*

```solidity
88:     function _calculateFee(uint256 amount) internal view returns (uint256) 

```


*GitHub* : [88](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L88-L88)

```solidity
100:     function _safeTransfer(address token, address to, uint256 value) internal 

```


*GitHub* : [100](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L100-L100)

```solidity
132:     function _calculatePaymentProRata(
133:         uint256 amount,
134:         uint256 elapsedTime,
135:         uint256 totalTime
136:     ) internal pure returns (uint256 renterAmount, uint256 lenderAmount) 

```


*GitHub* : [132](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L132-L132)

```solidity
159:     function _settlePaymentProRata(
160:         address token,
161:         uint256 amount,
162:         address lender,
163:         address renter,
164:         uint256 elapsedTime,
165:         uint256 totalTime
166:     ) internal 

```


*GitHub* : [159](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L159-L159)

```solidity
190:     function _settlePaymentInFull(
191:         address token,
192:         uint256 amount,
193:         SettleTo settleTo,
194:         address lender,
195:         address renter
196:     ) internal 

```


*GitHub* : [190](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L190-L190)

```solidity
215:     function _settlePayment(
216:         Item[] calldata items,
217:         OrderType orderType,
218:         address lender,
219:         address renter,
220:         uint256 start,
221:         uint256 end
222:     ) internal 

```


*GitHub* : [215](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L215-L215)

```solidity
292:     function _decreaseDeposit(address token, uint256 amount) internal 

```


*GitHub* : [292](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L292-L292)

```solidity
304:     function _increaseDeposit(address token, uint256 amount) internal 

```


*GitHub* : [304](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L304-L304)

```solidity
32:     function _insert(
33:         bytes memory rentalAssets,
34:         RentalId rentalId,
35:         uint256 rentalAssetAmount
36:     ) internal pure 

```


*GitHub* : [32](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L32-L32)

```solidity
96:     function _convertToStatic(
97:         bytes memory rentalAssetUpdates
98:     ) internal pure returns (RentalAssetUpdate[] memory updates) 

```


*GitHub* : [96](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L96-L96)

```solidity
32:     function _transferERC721(Item memory item, address recipient) private 

```


*GitHub* : [32](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L32-L32)

```solidity
42:     function _transferERC1155(Item memory item, address recipient) private 

```


*GitHub* : [42](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L42-L42)

```solidity
76:     function _validateFulfiller(
77:         address intendedFulfiller,
78:         address actualFulfiller
79:     ) internal pure 

```


*GitHub* : [76](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L76-L76)

```solidity
94:     function _validateProtocolSignatureExpiration(uint256 expiration) internal view 

```


*GitHub* : [94](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L94-L94)

```solidity
107:     function _recoverSignerFromPayload(
108:         bytes32 payloadHash,
109:         bytes memory signature
110:     ) internal view returns (address) 

```


*GitHub* : [107](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L107-L107)

```solidity
125:     function _deriveItemHash(Item memory item) internal view returns (bytes32) 

```


*GitHub* : [125](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L125-L125)

```solidity
147:     function _deriveHookHash(Hook memory hook) internal view returns (bytes32) 

```


*GitHub* : [147](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L147-L147)

```solidity
162:     function _deriveRentalOrderHash(
163:         RentalOrder memory order
164:     ) internal view returns (bytes32) 

```


*GitHub* : [162](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L162-L162)

```solidity
204:     function _deriveOrderFulfillmentHash(
205:         OrderFulfillment memory fulfillment
206:     ) internal view returns (bytes32) 

```


*GitHub* : [204](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L204-L204)

```solidity
218:     function _deriveOrderMetadataHash(
219:         OrderMetadata memory metadata
220:     ) internal view returns (bytes32) 

```


*GitHub* : [218](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L218-L218)

```solidity
248:     function _deriveRentPayloadHash(
249:         RentPayload memory payload
250:     ) internal view returns (bytes32) 

```


*GitHub* : [248](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L248-L248)

```solidity
273:     function _deriveDomainSeparator(
274:         bytes32 _eip712DomainTypeHash,
275:         bytes32 _nameHash,
276:         bytes32 _versionHash
277:     ) internal view virtual returns (bytes32) 

```


*GitHub* : [273](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L273-L273)

```solidity
298:     function _deriveTypehashes()
299:         internal
300:         view
301:         returns (
302:             bytes32 nameHash,
303:             bytes32 versionHash,
304:             bytes32 eip712DomainTypehash,
305:             bytes32 domainSeparator
306:         )
307:     

```


*GitHub* : [298](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L298-L298)

```solidity
339:     function _deriveRentalTypehashes()
340:         internal
341:         pure
342:         returns (
343:             bytes32 itemTypeHash,
344:             bytes32 hookTypeHash,
345:             bytes32 rentalOrderTypeHash,
346:             bytes32 orderFulfillmentTypeHash,
347:             bytes32 orderMetadataTypeHash,
348:             bytes32 rentPayloadTypeHash
349:         )
350:     

```


*GitHub* : [339](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L339-L339)

```solidity
165:     function _emitRentalOrderStarted(
166:         RentalOrder memory order,
167:         bytes32 orderHash,
168:         bytes memory extraData
169:     ) internal 

```


*GitHub* : [165](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L165-L165)

```solidity
195:     function _processBaseOrderOffer(
196:         Item[] memory rentalItems,
197:         SpentItem[] memory offers,
198:         uint256 startIndex
199:     ) internal pure 

```


*GitHub* : [195](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L195-L195)

```solidity
247:     function _processPayOrderOffer(
248:         Item[] memory rentalItems,
249:         SpentItem[] memory offers,
250:         uint256 startIndex
251:     ) internal pure 

```


*GitHub* : [247](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L247-L247)

```solidity
326:     function _processBaseOrderConsideration(
327:         Item[] memory rentalItems,
328:         ReceivedItem[] memory considerations,
329:         uint256 startIndex
330:     ) internal pure 

```


*GitHub* : [326](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L326-L326)

```solidity
367:     function _processPayeeOrderConsideration(
368:         ReceivedItem[] memory considerations
369:     ) internal pure 

```


*GitHub* : [367](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L367-L367)

```solidity
411:     function _convertToItems(
412:         SpentItem[] memory offers,
413:         ReceivedItem[] memory considerations,
414:         OrderType orderType
415:     ) internal pure returns (Item[] memory items) 

```


*GitHub* : [411](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L411-L411)

```solidity
464:     function _addHooks(
465:         Hook[] memory hooks,
466:         SpentItem[] memory offerItems,
467:         address rentalWallet
468:     ) internal 

```


*GitHub* : [464](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L464-L464)

```solidity
530:     function _rentFromZone(
531:         RentPayload memory payload,
532:         SeaportPayload memory seaportPayload
533:     ) internal 

```


*GitHub* : [530](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L530-L530)

```solidity
626:     function _isValidOrderMetadata(
627:         OrderMetadata memory metadata,
628:         bytes32 zoneHash
629:     ) internal view 

```


*GitHub* : [626](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L626-L626)

```solidity
647:     function _isValidSafeOwner(address owner, address safe) internal view 

```


*GitHub* : [647](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L647-L647)

```solidity
666:     function _checkExpectedRecipient(
667:         ReceivedItem memory execution,
668:         address expectedRecipient
669:     ) internal pure 

```


*GitHub* : [666](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L666-L666)

```solidity
691:     function _executionInvariantChecks(
692:         ReceivedItem[] memory executions,
693:         address expectedRentalSafe
694:     ) internal view 

```


*GitHub* : [691](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L691-L691)

```solidity
108:     function _loadValueFromCalldata(
109:         bytes memory data,
110:         uint256 offset
111:     ) private pure returns (bytes32 value) 

```


*GitHub* : [108](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L108-L108)

```solidity
126:     function _revertSelectorOnActiveRental(
127:         bytes4 selector,
128:         address safe,
129:         address token,
130:         uint256 tokenId
131:     ) private view 

```


*GitHub* : [126](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L126-L126)

```solidity
143:     function _revertNonWhitelistedExtension(address extension) private view 

```


*GitHub* : [143](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L143-L143)

```solidity
159:     function _forwardToHook(
160:         address hook,
161:         address safe,
162:         address to,
163:         uint256 value,
164:         bytes memory data
165:     ) private 

```


*GitHub* : [159](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L159-L159)

```solidity
195:     function _checkTransaction(address from, address to, bytes memory data) private view 

```


*GitHub* : [195](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L195-L195)

```solidity
111:     function _emitRentalOrderStopped(bytes32 seaportOrderHash, address stopper) internal 

```


*GitHub* : [111](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L111-L111)

```solidity
126:     function _validateRentalCanBeStoped(
127:         OrderType orderType,
128:         uint256 endTimestamp,
129:         address expectedLender
130:     ) internal view 

```


*GitHub* : [126](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L126-L126)

```solidity
166:     function _reclaimRentedItems(RentalOrder memory order) internal 

```


*GitHub* : [166](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L166-L166)

```solidity
194:     function _removeHooks(
195:         Hook[] calldata hooks,
196:         Item[] calldata rentalItems,
197:         address rentalWallet
198:     ) internal 

```


*GitHub* : [194](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L194-L194)

```solidity
180:     function getModuleAddress(Keycode keycode_) internal view returns (address) 

```


*GitHub* : [180](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L180-L180)

```solidity
277:     function executeAction(Actions action_, address target_) external onlyExecutor 

```


*GitHub* : [277](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L277-L277)

```solidity
310:     function grantRole(Role role_, address addr_) public onlyAdmin 

```


*GitHub* : [310](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L310-L310)

```solidity
333:     function revokeRole(Role role_, address addr_) public onlyAdmin 

```


*GitHub* : [333](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L333-L333)

```solidity
356:     function _installModule(Module newModule_) internal 

```


*GitHub* : [356](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L356-L356)

```solidity
383:     function _upgradeModule(Module newModule_) internal 

```


*GitHub* : [383](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L383-L383)

```solidity
418:     function _activatePolicy(Policy policy_) internal 

```


*GitHub* : [418](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L418-L418)

```solidity
457:     function _deactivatePolicy(Policy policy_) internal 

```


*GitHub* : [457](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L457-L457)

```solidity
508:     function _migrateKernel(Kernel newKernel_) internal 

```


*GitHub* : [508](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L508-L508)

```solidity
540:     function _reconfigurePolicies(Keycode keycode_) internal 

```


*GitHub* : [540](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L540-L540)

```solidity
560:     function _setPolicyPermissions(
561:         Policy policy_,
562:         Permissions[] memory requests_,
563:         bool grant_
564:     ) internal 

```


*GitHub* : [560](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L560-L560)

```solidity
586:     function _pruneFromDependents(Policy policy_) internal 

```


*GitHub* : [586](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L586-L586)
### [N-99]<a name="n-99"></a> Natspec @notice comments are missing from constructor

*There are 9 instance(s) of this issue:*

```solidity
79:     constructor(Kernel kernel_) Module(kernel_) 

```


*GitHub* : [79](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L79-L79)

```solidity
22:     constructor() 

```


*GitHub* : [22](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L22-L22)

```solidity
61:     constructor(Kernel kernel_) Policy(kernel_) 

```


*GitHub* : [61](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L61-L61)

```solidity
61:     constructor(Kernel kernel_) Policy(kernel_) Signer() Zone() 

```


*GitHub* : [61](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L61-L61)

```solidity
49:     constructor(
50:         Kernel kernel_,
51:         Stop stopPolicy_,
52:         Guard guardPolicy_,
53:         TokenCallbackHandler fallbackHandler_,
54:         SafeProxyFactory safeProxyFactory_,
55:         SafeL2 safeSingleton_
56:     ) Policy(kernel_) 

```


*GitHub* : [49](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Factory.sol#L49-L49)

```solidity
52:     constructor(Kernel kernel_) Policy(kernel_) Signer() Reclaimer() 

```


*GitHub* : [52](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L52-L52)

```solidity
79:     constructor(Kernel kernel_) 

```


*GitHub* : [79](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L79-L79)

```solidity
71:     constructor(Kernel kernel_) KernelAdapter(kernel_) 

```


*GitHub* : [71](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L71-L71)

```solidity
242:     constructor(address _executor, address _admin) 

```


*GitHub* : [242](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L242-L242)
### [N-100]<a name="n-100"></a> Natspec comments are missing from scope blocks

*There are 1 instance(s) of this issue:*

```solidity
377:         {
378:             
379:             bytes memory orderFulfillmentTypeString = abi.encodePacked(
380:                 "OrderFulfillment(address recipient)"
381:             );
382: 
383:             
384:             bytes memory orderMetadataTypeString = abi.encodePacked(
385:                 "OrderMetadata(uint8 orderType,uint256 rentDuration,Hook[] hooks,bytes emittedExtraData)"
386:             );
387: 
388:             
389:             bytes memory rentPayloadTypeString = abi.encodePacked(
390:                 "RentPayload(OrderFulfillment fulfillment,OrderMetadata metadata,uint256 expiration,address intendedFulfiller)"
391:             );
392: 
393:             
394:             rentPayloadTypeHash = keccak256(
395:                 abi.encodePacked(
396:                     rentPayloadTypeString,
397:                     orderMetadataTypeString,
398:                     orderFulfillmentTypeString
399:                 )
400:             );
401: 
402:             
403:             orderFulfillmentTypeHash = keccak256(orderFulfillmentTypeString);
404: 
405:             
406:             orderMetadataTypeHash = keccak256(orderMetadataTypeString);
407:         }

```


*GitHub* : [377](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L377-L377)
### [N-101]<a name="n-101"></a> Natspec comments are missing from assembly blocks

*There are 6 instance(s) of this issue:*

```solidity
40:         assembly {
41:             
42:             if eq(mload(rentalAssets), 0) {
43:                 
44:                 mstore(rentalAssets, 0x20)
45: 
46:                 
47:                 mstore(add(0x20, rentalAssets), 0x00)
48:             }
49: 
50:             
51:             
52:             let newByteDataSize := add(mload(rentalAssets), 0x40)
53: 
54:             
55:             let rentalAssetElementPtr := add(rentalAssets, 0x20)
56: 
57:             
58:             let elements := add(mload(rentalAssetElementPtr), 1)
59: 
60:             
61:             
62:             
63:             
64:             let newItemPosition := add(
65:                 rentalAssetElementPtr,
66:                 sub(mul(elements, 0x40), 0x20)
67:             )
68: 
69:             
70:             mstore(rentalAssets, newByteDataSize)
71: 
72:             
73:             mstore(rentalAssetElementPtr, elements)
74: 
75:             
76:             mstore(newItemPosition, _rentalId)
77: 
78:             
79:             mstore(add(newItemPosition, 0x20), rentalAssetAmount)
80: 
81:             
82:             
83:             mstore(0x40, add(newItemPosition, 0x40))
84:         }

```


*GitHub* : [40](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L40-L40)

```solidity
104:         assembly {
105:             
106:             
107:             
108:             
109:             rentalAssetUpdatePointer := add(0x20, rentalAssetUpdates)
110: 
111:             
112:             rentalAssetUpdateLength := mload(rentalAssetUpdatePointer)
113:         }

```


*GitHub* : [104](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Accumulator.sol#L104-L104)

```solidity
113:         assembly {
114:             value := mload(add(data, offset))
115:         }

```


*GitHub* : [113](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L113-L113)

```solidity
199:         assembly {
200:             selector := mload(add(data, 0x20))
201:         }

```


*GitHub* : [199](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol#L199-L199)

```solidity
53:         assembly {
54:             deploymentAddress := create2(
55:                 
56:                 callvalue(),
57:                 
58:                 add(initCode, 0x20),
59:                 
60:                 mload(initCode),
61:                 
62:                 salt
63:             )
64:         }

```


*GitHub* : [53](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L53-L53)

```solidity
111:        assembly {
112:             
113:             salt := or(
114:                 
115:                 shl(0x60, sender),
116:                 
117:                 shr(0xA0, data)
118:             )
119:         }

```


*GitHub* : [111](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Create2Deployer.sol#L111-L111)### Disputed Risk Issues


 ### [D-01]<a name="d-01"></a> Gas grief possible on unsafe external calls [EXP]
In Solidity, the use of low-level `call` methods can expose contracts to gas griefing attacks. The potential problem arises when the callee contract returns a large amount of data. This data is allocated in the memory of the calling contract, which pays for the gas costs. If the callee contract intentionally returns an enormous amount of data, the gas costs can skyrocket, causing the transaction to fail due to an Out of Gas error. Therefore, it's advisable to limit the use of `call` when interacting with untrusted contracts, or ensure that the callee's returned data size is capped or known in advance to prevent unexpected high gas costs.

*There are 1 instance(s) of this issue:*

```solidity
100:     function _safeTransfer(address token, address to, uint256 value) internal { // <= FOUND
101:         
102:         (bool success, bytes memory data) = token.call(
103:             abi.encodeWithSelector(IERC20.transfer.selector, to, value)
104:         );
105: 
106:         
107:         
108:         
109:         
110:         
111:         
112:         
113:         
114:         
115:         if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
116:             revert Errors.PaymentEscrowModule_PaymentTransferFailed(token, to, value);
117:         }
118:     }

```


*GitHub* : [100](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L100-L100)
### [D-02]<a name="d-02"></a> Function with two array parameter missing a length check [EXP]
In Solidity, if two array parameters are used within a function and one of their lengths is used as the for-loop range, it's essential to have a length check. If the arrays are not the same length, you could experience out-of-bounds errors or unintended behavior. This could happen if the function tries to access an index that doesn't exist in the shorter array.

Resolution: Always validate that the lengths of both arrays are the same before entering the loop. Add a require statement at the start of the function to check that both arrays are of equal length. This helps maintain the integrity of the function and prevents potential errors due to differing array lengths. This requirement ensures the function fails early if the arrays don't match, rather than failing unpredictably or silently during execution.

*There are 1 instance(s) of this issue:*

```solidity
464:     function _addHooks(
465:         Hook[] memory hooks,
466:         SpentItem[] memory offerItems,
467:         address rentalWallet
468:     ) internal {
469:         
470:         address target;
471:         uint256 itemIndex;
472:         SpentItem memory offer;
473: 
474:         
475:         for (uint256 i = 0; i < hooks.length; ++i) { // <= FOUND
476:             
477:             target = hooks[i].target;
478: 
479:             
480:             if (!STORE.hookOnStart(target)) {
481:                 revert Errors.Shared_DisabledHook(target);
482:             }
483: 
484:             
485:             itemIndex = hooks[i].itemIndex;
486: 
487:             
488:             offer = offerItems[itemIndex];
489: 
490:             
491:             if (!offer.isRental()) {
492:                 revert Errors.Shared_NonRentalHookItem(itemIndex);
493:             }
494: 
495:             
496:             try
497:                 IHook(target).onStart(
498:                     rentalWallet,
499:                     offer.token,
500:                     offer.identifier,
501:                     offer.amount,
502:                     hooks[i].extraData
503:                 )
504:             {} catch Error(string memory revertReason) {
505:                 
506:                 revert Errors.Shared_HookFailString(revertReason);
507:             } catch Panic(uint256 errorCode) {
508:                 
509:                 string memory stringErrorCode = LibString.toString(errorCode);
510: 
511:                 
512:                 revert Errors.Shared_HookFailString(
513:                     string.concat("Hook reverted: Panic code ", stringErrorCode)

```


*GitHub* : [464](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L464-L475)
### [D-03]<a name="d-03"></a> Code does not follow the best practice of check-effects-interaction [EXP]
The "check-effects-interaction" pattern is a best practice in smart contract development, emphasizing the order of operations in functions to prevent reentrancy attacks. Violations arise when a function interacts with external contracts before settling internal state changes or checks. This misordering can expose the contract to potential threats. To adhere to this pattern, first ensure all conditions or checks are satisfied, then update any internal states, and only after these steps, interact with external contracts or addresses. Rearranging operations to this recommended sequence bolsters contract security and aligns with established best practices in the Ethereum community.

*There are 3 instance(s) of this issue:*

```solidity
294:     function updateHookPath(address to, address hook) external onlyByProxy permissioned { // <= FOUND
295:         
296:         if (to.code.length == 0) revert Errors.StorageModule_NotContract(to); // <= FOUND
297: 
298:         
299:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook); // <= FOUND
300: 
301:         
302:         _contractToHook[to] = hook;
303:     }

```


*GitHub* : [294](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L294-L299)

```solidity
294:     function updateHookPath(address to, address hook) external onlyByProxy permissioned { // <= FOUND
295:         
296:         if (to.code.length == 0) revert Errors.StorageModule_NotContract(to); // <= FOUND
297: 
298:         
299:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook); // <= FOUND
300: 
301:         
302:         _contractToHook[to] = hook;
303:     }

```


*GitHub* : [294](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L294-L299)

```solidity
294:     function updateHookPath(address to, address hook) external onlyByProxy permissioned { // <= FOUND
295:         
296:         if (to.code.length == 0) revert Errors.StorageModule_NotContract(to); // <= FOUND
297: 
298:         
299:         if (hook.code.length == 0) revert Errors.StorageModule_NotContract(hook); // <= FOUND
300: 
301:         
302:         _contractToHook[to] = hook;
303:     }

```


*GitHub* : [294](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L294-L299)
### [D-04]<a name="d-04"></a> Events may be emitted out of order due to code not follow the best practice of check-effects-interaction [EXP]
The "check-effects-interaction" pattern also impacts event ordering. When a contract doesn't adhere to this pattern, events might be emitted in a sequence that doesn't reflect the actual logical flow of operations. This can cause confusion during event tracking, potentially leading to erroneous off-chain interpretations. To rectify this, always ensure that checks are performed first, state modifications come next, and interactions with external contracts or addresses are done last. This will ensure events are emitted in a logical, consistent manner, providing a clear and accurate chronological record of on-chain actions for off-chain systems and observers.

*There are 1 instance(s) of this issue:*

```solidity
397:     function skim(address token, address to) external onlyByProxy permissioned { // <= FOUND
398:         
399:         uint256 syncedBalance = balanceOf[token];
400: 
401:         
402:         uint256 trueBalance = IERC20(token).balanceOf(address(this)); // <= FOUND
403: 
404:         
405:         uint256 skimmedBalance = trueBalance - syncedBalance;
406: 
407:         
408:         _safeTransfer(token, to, skimmedBalance);
409: 
410:         
411:         emit Events.FeeTaken(token, skimmedBalance); // <= FOUND
412:     }

```


*GitHub* : [397](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L397-L411)
### [D-05]<a name="d-05"></a> Consider merging sequential for loops [EXP]
Merging multiple `for` loops within a function in Solidity can enhance efficiency and reduce gas costs, especially when they share a common iterating variable or perform related operations. By minimizing redundant iterations over the same data set, execution becomes more cost-effective. However, while merging can optimize gas usage and simplify logic, it may also increase code complexity. Therefore, careful balance between optimization and maintainability is essential, along with thorough testing to ensure the refactored code behaves as expected.

*There are 4 instance(s) of this issue:*

```solidity
244:     function removeRentalsBatch(
245:         bytes32[] calldata orderHashes,
246:         RentalAssetUpdate[] calldata rentalAssetUpdates
247:     ) external onlyByProxy permissioned {
248:         
249:         for (uint256 i = 0; i < orderHashes.length; ++i) { // <= FOUND
250:             
251:             if (!orders[orderHashes[i]]) {
252:                 revert Errors.StorageModule_OrderDoesNotExist(orderHashes[i]);
253:             } else {
254:                 
255:                 delete orders[orderHashes[i]];
256:             }
257:         }
258: 
259:         
260:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) { // <= FOUND
261:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
262: 
263:             
264:             rentedAssets[asset.rentalId] -= asset.amount;
265:         }
266:     }

```


*GitHub* : [244](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L244-L260)

```solidity
244:     function removeRentalsBatch(
245:         bytes32[] calldata orderHashes,
246:         RentalAssetUpdate[] calldata rentalAssetUpdates
247:     ) external onlyByProxy permissioned {
248:         
249:         for (uint256 i = 0; i < orderHashes.length; ++i) { // <= FOUND
250:             
251:             if (!orders[orderHashes[i]]) {
252:                 revert Errors.StorageModule_OrderDoesNotExist(orderHashes[i]);
253:             } else {
254:                 
255:                 delete orders[orderHashes[i]];
256:             }
257:         }
258: 
259:         
260:         for (uint256 i = 0; i < rentalAssetUpdates.length; ++i) { // <= FOUND
261:             RentalAssetUpdate memory asset = rentalAssetUpdates[i];
262: 
263:             
264:             rentedAssets[asset.rentalId] -= asset.amount;
265:         }
266:     }

```


*GitHub* : [244](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L244-L260)

```solidity
162:     function _deriveRentalOrderHash(
163:         RentalOrder memory order
164:     ) internal view returns (bytes32) {
165:         
166:         bytes32[] memory itemHashes = new bytes32[](order.items.length);
167:         bytes32[] memory hookHashes = new bytes32[](order.hooks.length);
168: 
169:         
170:         for (uint256 i = 0; i < order.items.length; ++i) { // <= FOUND
171:             
172:             itemHashes[i] = _deriveItemHash(order.items[i]);
173:         }
174: 
175:         
176:         for (uint256 i = 0; i < order.hooks.length; ++i) { // <= FOUND
177:             
178:             hookHashes[i] = _deriveHookHash(order.hooks[i]);
179:         }
180: 
181:         return
182:             keccak256(
183:                 abi.encode(
184:                     _RENTAL_ORDER_TYPEHASH,
185:                     order.seaportOrderHash,
186:                     keccak256(abi.encodePacked(itemHashes)),
187:                     keccak256(abi.encodePacked(hookHashes)),
188:                     order.orderType,
189:                     order.lender,
190:                     order.renter,
191:                     order.startTimestamp,
192:                     order.endTimestamp
193:                 )
194:             );
195:     }

```


*GitHub* : [162](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L162-L176)

```solidity
162:     function _deriveRentalOrderHash(
163:         RentalOrder memory order
164:     ) internal view returns (bytes32) {
165:         
166:         bytes32[] memory itemHashes = new bytes32[](order.items.length);
167:         bytes32[] memory hookHashes = new bytes32[](order.hooks.length);
168: 
169:         
170:         for (uint256 i = 0; i < order.items.length; ++i) { // <= FOUND
171:             
172:             itemHashes[i] = _deriveItemHash(order.items[i]);
173:         }
174: 
175:         
176:         for (uint256 i = 0; i < order.hooks.length; ++i) { // <= FOUND
177:             
178:             hookHashes[i] = _deriveHookHash(order.hooks[i]);
179:         }
180: 
181:         return
182:             keccak256(
183:                 abi.encode(
184:                     _RENTAL_ORDER_TYPEHASH,
185:                     order.seaportOrderHash,
186:                     keccak256(abi.encodePacked(itemHashes)),
187:                     keccak256(abi.encodePacked(hookHashes)),
188:                     order.orderType,
189:                     order.lender,
190:                     order.renter,
191:                     order.startTimestamp,
192:                     order.endTimestamp
193:                 )
194:             );
195:     }

```


*GitHub* : [162](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L162-L176)
### [D-06]<a name="d-06"></a> Avoid updating storage when the value hasn't changed [EXP]

*There are 1 instance(s) of this issue:*

```solidity
586:     function _pruneFromDependents(Policy policy_) internal { // <= FOUND
587:         
588:         Keycode[] memory dependencies = policy_.configureDependencies();
589:         uint256 depcLength = dependencies.length;
590: 
591:         
592:         for (uint256 i; i < depcLength; ++i) {
593:             
594:             Keycode keycode = dependencies[i];
595:             Policy[] storage dependents = moduleDependents[keycode]; // <= FOUND
596: 
597:             
598:             uint256 origIndex = getDependentIndex[keycode][policy_];
599: 
600:             
601:             Policy lastPolicy = dependents[dependents.length - 1];
602: 
603:             
604:             dependents[origIndex] = lastPolicy;
605: 
606:             
607:             
608:             dependents.pop();
609: 
610:             
611:             getDependentIndex[keycode][lastPolicy] = origIndex;
612: 
613:             
614:             delete getDependentIndex[keycode][policy_];
615:         }
616:     }

```


*GitHub* : [586](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L586-L595)
### [D-07]<a name="d-07"></a> Multiple accesses of the same mapping/array key/index should be cached [EXP]
Caching repeated accesses to the same mapping or array key/index in smart contracts can lead to significant gas savings. In Solidity, each read operation from storage (like accessing a value in a mapping or array using a key or index) costs gas. By storing the accessed value in a local variable and reusing it within the function, you avoid multiple expensive storage read operations. This practice is particularly beneficial in loops or functions with multiple reads of the same data. Implementing this caching approach enhances efficiency and reduces transaction costs, which is crucial for optimizing smart contract performance and user experience on the blockchain.

*There are 6 instance(s) of this issue:*

```solidity
310:     function grantRole(Role role_, address addr_) public onlyAdmin {
311:         
312:         if (hasRole[addr_][role_]) // <= FOUND
313:             revert Errors.Kernel_AddressAlreadyHasRole(addr_, role_);
314: 
315:         
316:         ensureValidRole(role_);
317: 
318:         
319:         if (!isRole[role_]) isRole[role_] = true; // <= FOUND
320: 
321:         
322:         hasRole[addr_][role_] = true; // <= FOUND
323: 
324:         emit Events.RoleGranted(role_, addr_);
325:     }

```


*GitHub* : [310](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L310-L322)

```solidity
310:     function grantRole(Role role_, address addr_) public onlyAdmin {
311:         
312:         if (hasRole[addr_][role_]) // <= FOUND
313:             revert Errors.Kernel_AddressAlreadyHasRole(addr_, role_);
314: 
315:         
316:         ensureValidRole(role_);
317: 
318:         
319:         if (!isRole[role_]) isRole[role_] = true; // <= FOUND
320: 
321:         
322:         hasRole[addr_][role_] = true; // <= FOUND
323: 
324:         emit Events.RoleGranted(role_, addr_);
325:     }

```


*GitHub* : [310](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L310-L322)

```solidity
333:     function revokeRole(Role role_, address addr_) public onlyAdmin {
334:         
335:         if (!isRole[role_]) revert Errors.Kernel_RoleDoesNotExist(role_); // <= FOUND
336: 
337:         
338:         if (!hasRole[addr_][role_]) // <= FOUND
339:             revert Errors.Kernel_AddressDoesNotHaveRole(addr_, role_);
340: 
341:         
342:         hasRole[addr_][role_] = false; // <= FOUND
343: 
344:         emit Events.RoleRevoked(role_, addr_);
345:     }

```


*GitHub* : [333](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L333-L342)

```solidity
333:     function revokeRole(Role role_, address addr_) public onlyAdmin {
334:         
335:         if (!isRole[role_]) revert Errors.Kernel_RoleDoesNotExist(role_); // <= FOUND
336: 
337:         
338:         if (!hasRole[addr_][role_]) // <= FOUND
339:             revert Errors.Kernel_AddressDoesNotHaveRole(addr_, role_);
340: 
341:         
342:         hasRole[addr_][role_] = false; // <= FOUND
343: 
344:         emit Events.RoleRevoked(role_, addr_);
345:     }

```


*GitHub* : [333](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L333-L342)

```solidity
333:     function revokeRole(Role role_, address addr_) public onlyAdmin {
334:         
335:         if (!isRole[role_]) revert Errors.Kernel_RoleDoesNotExist(role_); // <= FOUND
336: 
337:         
338:         if (!hasRole[addr_][role_]) // <= FOUND
339:             revert Errors.Kernel_AddressDoesNotHaveRole(addr_, role_);
340: 
341:         
342:         hasRole[addr_][role_] = false; // <= FOUND
343: 
344:         emit Events.RoleRevoked(role_, addr_);
345:     }

```


*GitHub* : [333](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L333-L342)

```solidity
333:     function revokeRole(Role role_, address addr_) public onlyAdmin {
334:         
335:         if (!isRole[role_]) revert Errors.Kernel_RoleDoesNotExist(role_); // <= FOUND
336: 
337:         
338:         if (!hasRole[addr_][role_]) // <= FOUND
339:             revert Errors.Kernel_AddressDoesNotHaveRole(addr_, role_);
340: 
341:         
342:         hasRole[addr_][role_] = false; // <= FOUND
343: 
344:         emit Events.RoleRevoked(role_, addr_);
345:     }

```


*GitHub* : [333](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L333-L342)
### [D-08]<a name="d-08"></a> The result of a function call should be cached rather than re-calling the function [EXP-0]
External calls in Solidity are costly in terms of gas usage. This can significantly impact contract efficiency and cost. Functions that make repetitive calls to fetch the same data from other contracts can cause unnecessary gas expenditure. To optimize this, it's advisable to store the returned value of these function calls in a state variable, essentially caching the data. This data can be updated at regular intervals or under specific conditions instead of fetching it from the external contract on every invocation. Be sure to analyze the frequency of data change in the external contract to balance data freshness with gas efficiency when implementing caching.

*There are 1 instance(s) of this issue:*

```solidity
215:     function _settlePayment(
216:         Item[] calldata items,
217:         OrderType orderType,
218:         address lender,
219:         address renter,
220:         uint256 start,
221:         uint256 end
222:     ) internal {
223:         
224:         uint256 elapsedTime = block.timestamp - start;
225:         uint256 totalTime = end - start;
226: 
227:         
228:         bool isRentalOver = elapsedTime >= totalTime;
229: 
230:         
231:         for (uint256 i = 0; i < items.length; ++i) {
232:             
233:             Item memory item = items[i];
234: 
235:             
236:             if (item.isERC20()) {
237:                 
238:                 
239:                 uint256 paymentAmount = item.amount;
240: 
241:                 
242:                 if (fee != 0) {
243:                     
244:                     uint256 paymentFee = _calculateFee(paymentAmount);
245: 
246:                     
247:                     paymentAmount -= paymentFee;
248:                 }
249: 
250:                 
251:                 
252:                 _decreaseDeposit(item.token, item.amount);
253: 
254:                 
255:                 if (orderType.isPayOrder() && !isRentalOver) { // <= FOUND
256:                     
257:                     _settlePaymentProRata(
258:                         item.token,
259:                         paymentAmount,
260:                         lender,
261:                         renter,
262:                         elapsedTime,
263:                         totalTime
264:                     );
265:                 }
266:                 
267:                 else if (
268:                     (orderType.isPayOrder() && isRentalOver) || orderType.isBaseOrder() // <= FOUND
269:                 ) {
270:                     
271:                     _settlePaymentInFull(
272:                         item.token,
273:                         paymentAmount,
274:                         item.settleTo,
275:                         lender,
276:                         renter
277:                     );
278:                 } else {
279:                     revert Errors.Shared_OrderTypeNotSupported(uint8(orderType));
280:                 }
281:             }
282:         }
283:     }

```


*GitHub* : [215](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L215-L268)
### [D-09]<a name="d-09"></a> Non constant/immutable state variables are missing a setter post deployment [EXP-1]
Non-constant or non-immutable state variables lacking a setter function can create inflexibility in contract operations. If there's no way to update these variables post-deployment, the contract might not adapt to changing conditions or requirements, which can be a significant drawback, especially in upgradable or long-lived contracts. To resolve this, implement setter functions guarded by appropriate access controls, like `onlyOwner` or similar modifiers, so that these variables can be updated as required while maintaining security. This enables smoother contract maintenance and feature upgrades.

*There are 1 instance(s) of this issue:*

```solidity
90: function KEYCODE() public pure virtual returns (Keycode);

```


*GitHub* : [90](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L90-L90)
### [D-10]<a name="d-10"></a> State variables used within a function more than once should be cached to save gas [EXP-1]
Cache such variables and perform operations on them, if operations include modifications to the state variable(s) then remember to equate the state variable to it's cached counterpart at the end

*There are 2 instance(s) of this issue:*

```solidity
72:     function configureDependencies() // <= FOUND
73:         external
74:         override
75:         onlyKernel
76:         returns (Keycode[] memory dependencies)
77:     {
78:         dependencies = new Keycode[](2);
79: 
80:         dependencies[0] = toKeycode("STORE"); // <= FOUND
81:         STORE = Storage(getModuleAddress(toKeycode("STORE"))); // <= FOUND
82: 
83:         dependencies[1] = toKeycode("ESCRW"); // <= FOUND
84:         ESCRW = PaymentEscrow(getModuleAddress(toKeycode("ESCRW"))); // <= FOUND
85:     }

```


*GitHub* : [72](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L72-L84)

```solidity
72:     function configureDependencies() // <= FOUND
73:         external
74:         override
75:         onlyKernel
76:         returns (Keycode[] memory dependencies)
77:     {
78:         dependencies = new Keycode[](2);
79: 
80:         dependencies[0] = toKeycode("STORE"); // <= FOUND
81:         STORE = Storage(getModuleAddress(toKeycode("STORE"))); // <= FOUND
82: 
83:         dependencies[1] = toKeycode("ESCRW"); // <= FOUND
84:         ESCRW = PaymentEscrow(getModuleAddress(toKeycode("ESCRW"))); // <= FOUND
85:     }

```


*GitHub* : [72](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Create.sol#L72-L84)
### [D-11]<a name="d-11"></a> Using abi.encodePacked can result in hash collision when used in hashing functions [EXP-2]
Consider using abi.encode as this pads data to 32 byte segments

*There are 5 instance(s) of this issue:*

```solidity
298:     function _deriveTypehashes()
299:         internal
300:         view
301:         returns (
302:             bytes32 nameHash,
303:             bytes32 versionHash,
304:             bytes32 eip712DomainTypehash,
305:             bytes32 domainSeparator
306:         )
307:     {
308:         
309:         nameHash = keccak256(bytes(_NAME));
310: 
311:         
312:         versionHash = keccak256(bytes(_VERSION));
313: 
314:         
315:         eip712DomainTypehash = keccak256(
316:             abi.encodePacked( // <= FOUND
317:                 "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
318:             )
319:         );
320: 
321:         
322:         domainSeparator = _deriveDomainSeparator(
323:             eip712DomainTypehash,
324:             nameHash,
325:             versionHash
326:         );
327:     }

```


*GitHub* : [316](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L316-L316)

```solidity
162:     function _deriveRentalOrderHash(
163:         RentalOrder memory order
164:     ) internal view returns (bytes32) {
165:         
166:         bytes32[] memory itemHashes = new bytes32[](order.items.length);
167:         bytes32[] memory hookHashes = new bytes32[](order.hooks.length);
168: 
169:         
170:         for (uint256 i = 0; i < order.items.length; ++i) {
171:             
172:             itemHashes[i] = _deriveItemHash(order.items[i]);
173:         }
174: 
175:         
176:         for (uint256 i = 0; i < order.hooks.length; ++i) {
177:             
178:             hookHashes[i] = _deriveHookHash(order.hooks[i]);
179:         }
180: 
181:         return
182:             keccak256(
183:                 abi.encode(
184:                     _RENTAL_ORDER_TYPEHASH,
185:                     order.seaportOrderHash,
186:                     keccak256(abi.encodePacked(itemHashes)), // <= FOUND
187:                     keccak256(abi.encodePacked(hookHashes)), // <= FOUND
188:                     order.orderType,
189:                     order.lender,
190:                     order.renter,
191:                     order.startTimestamp,
192:                     order.endTimestamp
193:                 )
194:             );
195:     }

```


*GitHub* : [186](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L186-L187)

```solidity
162:     function _deriveRentalOrderHash(
163:         RentalOrder memory order
164:     ) internal view returns (bytes32) {
165:         
166:         bytes32[] memory itemHashes = new bytes32[](order.items.length);
167:         bytes32[] memory hookHashes = new bytes32[](order.hooks.length);
168: 
169:         
170:         for (uint256 i = 0; i < order.items.length; ++i) {
171:             
172:             itemHashes[i] = _deriveItemHash(order.items[i]);
173:         }
174: 
175:         
176:         for (uint256 i = 0; i < order.hooks.length; ++i) {
177:             
178:             hookHashes[i] = _deriveHookHash(order.hooks[i]);
179:         }
180: 
181:         return
182:             keccak256(
183:                 abi.encode(
184:                     _RENTAL_ORDER_TYPEHASH,
185:                     order.seaportOrderHash,
186:                     keccak256(abi.encodePacked(itemHashes)), // <= FOUND
187:                     keccak256(abi.encodePacked(hookHashes)), // <= FOUND
188:                     order.orderType,
189:                     order.lender,
190:                     order.renter,
191:                     order.startTimestamp,
192:                     order.endTimestamp
193:                 )
194:             );
195:     }

```


*GitHub* : [186](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L186-L187)

```solidity
162:     function _deriveRentalOrderHash(
163:         RentalOrder memory order
164:     ) internal view returns (bytes32) {
165:         
166:         bytes32[] memory itemHashes = new bytes32[](order.items.length);
167:         bytes32[] memory hookHashes = new bytes32[](order.hooks.length);
168: 
169:         
170:         for (uint256 i = 0; i < order.items.length; ++i) {
171:             
172:             itemHashes[i] = _deriveItemHash(order.items[i]);
173:         }
174: 
175:         
176:         for (uint256 i = 0; i < order.hooks.length; ++i) {
177:             
178:             hookHashes[i] = _deriveHookHash(order.hooks[i]);
179:         }
180: 
181:         return
182:             keccak256(
183:                 abi.encode(
184:                     _RENTAL_ORDER_TYPEHASH,
185:                     order.seaportOrderHash,
186:                     keccak256(abi.encodePacked(itemHashes)), // <= FOUND
187:                     keccak256(abi.encodePacked(hookHashes)), // <= FOUND
188:                     order.orderType,
189:                     order.lender,
190:                     order.renter,
191:                     order.startTimestamp,
192:                     order.endTimestamp
193:                 )
194:             );
195:     }

```


*GitHub* : [186](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L186-L187)

```solidity
162:     function _deriveRentalOrderHash(
163:         RentalOrder memory order
164:     ) internal view returns (bytes32) {
165:         
166:         bytes32[] memory itemHashes = new bytes32[](order.items.length);
167:         bytes32[] memory hookHashes = new bytes32[](order.hooks.length);
168: 
169:         
170:         for (uint256 i = 0; i < order.items.length; ++i) {
171:             
172:             itemHashes[i] = _deriveItemHash(order.items[i]);
173:         }
174: 
175:         
176:         for (uint256 i = 0; i < order.hooks.length; ++i) {
177:             
178:             hookHashes[i] = _deriveHookHash(order.hooks[i]);
179:         }
180: 
181:         return
182:             keccak256(
183:                 abi.encode(
184:                     _RENTAL_ORDER_TYPEHASH,
185:                     order.seaportOrderHash,
186:                     keccak256(abi.encodePacked(itemHashes)), // <= FOUND
187:                     keccak256(abi.encodePacked(hookHashes)), // <= FOUND
188:                     order.orderType,
189:                     order.lender,
190:                     order.renter,
191:                     order.startTimestamp,
192:                     order.endTimestamp
193:                 )
194:             );
195:     }

```


*GitHub* : [186](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L186-L187)
### [D-12]<a name="d-12"></a> Getting a bool return value does not confirm the existence of a function in an external call [EXP-2]
External calls to contracts using `address.call()` might return a boolean indicating success or failure. However, this boolean doesn't guarantee the existence of a called function. If a function isn't present, the call won't revert but will simply return `false`. This behavior might lead developers into mistakenly believing they're interacting with a legitimate or expected function, whereas it might not exist at all—a scenario sometimes termed as "phantom functions". Resolution: Instead of solely relying on the boolean, further validate the contract you're interacting with, or use interfaces or abstract contracts to enforce the existence of expected functions.

*There are 2 instance(s) of this issue:*

```solidity
function _safeTransfer(address token, address to, uint256 value) internal { // <= FOUND
   (bool success, bytes memory data) = token.call(  abi.encodeWithSelector(IERC20.transfer.selector, to, value) );
                  if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {             revert Errors.PaymentEscrowModule_PaymentTransferFailed(token, to, value);
 }
}

```


*GitHub* :

```solidity
function _safeTransfer(address token, address to, uint256 value) internal { // <= FOUND
   (bool success, bytes memory data) = token.call(  abi.encodeWithSelector(IERC20.transfer.selector, to, value) );
                  if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {             revert Errors.PaymentEscrowModule_PaymentTransferFailed(token, to, value);
 }
}

```


*GitHub* :
### [D-13]<a name="d-13"></a> No limits when setting fees [EXP-3]
When settings fees state variables, ensure there a require checks in place to prevent incorrect values from being set. This is particularly important when dealing with fee values as without checks fees can be set to 100%

*There are 2 instance(s) of this issue:*

```solidity
380:     function setFee(uint256 feeNumerator) external onlyByProxy permissioned {
381:         
382:         if (feeNumerator > 10000) {
383:             revert Errors.PaymentEscrow_InvalidFeeNumerator();
384:         }
385: 
386:         
387:         fee = feeNumerator;
388:     }

```


*GitHub* : [380](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L380-L380)

```solidity
380:     function setFee(uint256 feeNumerator) external onlyByProxy permissioned {
381:         
382:         if (feeNumerator > 10000) {
383:             revert Errors.PaymentEscrow_InvalidFeeNumerator();
384:         }
385: 
386:         
387:         fee = feeNumerator;
388:     }

```


*GitHub* : [380](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L380-L380)
### [D-14]<a name="d-14"></a> Employ Explicit Casting to Bytes or Bytes32 for Enhanced Code Clarity and Meaning [EXP-3]
Smart contracts are complex entities, and clarity in their operations is fundamental to ensure that they function as intended. Casting a single argument instead of utilizing 'abi.encodePacked()' improves the transparency of the operation. It elucidates the intent of the code, reducing ambiguity and making it easier for auditors and developers to understand the code’s purpose. Such practices promote readability and maintainability, thus reducing the likelihood of errors and misunderstandings. Therefore, it's recommended to employ explicit casts for single arguments where possible, to increase the contract's comprehensibility and ensure a smoother review process.

*There are 1 instance(s) of this issue:*

```solidity
298:     function _deriveTypehashes()
299:         internal
300:         view
301:         returns (
302:             bytes32 nameHash,
303:             bytes32 versionHash,
304:             bytes32 eip712DomainTypehash,
305:             bytes32 domainSeparator
306:         )
307:     {
308:         
309:         nameHash = keccak256(bytes(_NAME));
310: 
311:         
312:         versionHash = keccak256(bytes(_VERSION));
313: 
314:         
315:         eip712DomainTypehash = keccak256(
316:             abi.encodePacked( // <= FOUND
317:                 "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
318:             )
319:         );
320: 
321:         
322:         domainSeparator = _deriveDomainSeparator(
323:             eip712DomainTypehash,
324:             nameHash,
325:             versionHash
326:         );
327:     }

```


*GitHub* : [316](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Signer.sol#L316-L316)
### [D-15]<a name="d-15"></a> Use assembly to write address storage values [EXP-3]
Using assembly to directly write storage values can be a gas-saving optimization, bypassing some of Solidity's overhead. While this can lead to reduced transaction costs, it introduces risks, as assembly lacks the safety checks inherent in high-level Solidity. Incorrect use can lead to critical vulnerabilities. If opting for this gas optimization, ensure that: 1) The assembly block is well-documented, detailing its purpose and operation; 2) Thorough tests are written, covering all potential edge cases; and 3) A meticulous code review is conducted by developers experienced in Ethereum assembly to ensure there are no oversights or unintended consequences.

*There are 1 instance(s) of this issue:*

```solidity
242:     constructor(address _executor, address _admin) { // <= FOUND
243:         executor = _executor; // <= FOUND
244:         admin = _admin; // <= FOUND
245:     }

```


*GitHub* : [242](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/Kernel.sol#L242-L244)
### [D-16]<a name="d-16"></a> Using bools for storage incurs overhead [EXP-3]
Using boolean variables (`bool`) for storage in Solidity can incur overhead due to the way data is packed in Ethereum's storage layout. A `bool` takes a full storage slot, even though it represents only a true or false value. This leads to inefficient usage of storage space and potentially higher gas costs. To resolve this issue, developers can use bit fields or uint8/uint256 to pack multiple boolean values into a single storage slot. By employing such optimization techniques, it's possible to save on storage space and reduce gas costs, making the contract more efficient.

*There are 3 instance(s) of this issue:*

```solidity
20:     
25:     mapping(bytes32 orderHash => bool isActive) public orders; // <= FOUND

```


*GitHub* : [20](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L20-L25)

```solidity
20:     
25:     mapping(bytes32 orderHash => bool isActive) public orders; // <= FOUND

```


*GitHub* : [20](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L20-L25)

```solidity
20:     
25:     mapping(bytes32 orderHash => bool isActive) public orders; // <= FOUND

```


*GitHub* : [20](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/Storage.sol#L20-L25)
### [D-17]<a name="d-17"></a> Loss of precision
Dividing by large integers in Solidity may cause a loss of precision due to the inherent limitations of fixed-point arithmetic in the Ethereum Virtual Machine (EVM). Solidity, like most programming languages, uses integer division, which truncates any decimal portion of the result. When dividing by large integers, the quotient can have a significant decimal component, but this is discarded, leading to an imprecise outcome. This loss of precision can have unintended consequences in smart contracts, especially in financial applications where accurate calculations are crucial. To mitigate this issue, developers should use appropriate scaling factors or specialized libraries that provide safe and precise arithmetic operations.

*There are 1 instance(s) of this issue:*

```solidity
132:     function _calculatePaymentProRata(
133:         uint256 amount,
134:         uint256 elapsedTime,
135:         uint256 totalTime
136:     ) internal pure returns (uint256 renterAmount, uint256 lenderAmount) {
137:         
138:         uint256 numerator = (amount * elapsedTime) * 1000;
139: 
140:         
141:         
142:         renterAmount = ((numerator / totalTime) + 500) / 1000; // <= FOUND
143: 
144:         
145:         lenderAmount = amount - renterAmount;
146:     }

```


*GitHub* : [142](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L142-L142)
### [D-18]<a name="d-18"></a> For loops in public or external functions should be avoided due to high gas costs and possible DOS
In Solidity, for loops can potentially cause Denial of Service (DoS) attacks if not handled carefully. DoS attacks can occur when an attacker intentionally exploits the gas cost of a function, causing it to run out of gas or making it too expensive for other users to call. Below are some scenarios where for loops can lead to DoS attacks: Nested for loops can become exceptionally gas expensive and should be used sparingly

*There are 4 instance(s) of this issue:*

```solidity
337:     function settlePaymentBatch(
338:         RentalOrder[] calldata orders
339:     ) external onlyByProxy permissioned {
340:         
341:         for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND
342:             
343:             _settlePayment(
344:                 orders[i].items,
345:                 orders[i].orderType,
346:                 orders[i].lender,
347:                 orders[i].renter,
348:                 orders[i].startTimestamp,
349:                 orders[i].endTimestamp
350:             );
351:         }
352:     }

```


*GitHub* : [341](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L341-L341)

```solidity
337:     function settlePaymentBatch(
338:         RentalOrder[] calldata orders
339:     ) external onlyByProxy permissioned {
340:         
341:         for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND
342:             
343:             _settlePayment(
344:                 orders[i].items,
345:                 orders[i].orderType,
346:                 orders[i].lender,
347:                 orders[i].renter,
348:                 orders[i].startTimestamp,
349:                 orders[i].endTimestamp
350:             );
351:         }
352:     }

```


*GitHub* : [341](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L341-L341)

```solidity
337:     function settlePaymentBatch(
338:         RentalOrder[] calldata orders
339:     ) external onlyByProxy permissioned {
340:         
341:         for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND
342:             
343:             _settlePayment(
344:                 orders[i].items,
345:                 orders[i].orderType,
346:                 orders[i].lender,
347:                 orders[i].renter,
348:                 orders[i].startTimestamp,
349:                 orders[i].endTimestamp
350:             );
351:         }
352:     }

```


*GitHub* : [341](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L341-L341)

```solidity
337:     function settlePaymentBatch(
338:         RentalOrder[] calldata orders
339:     ) external onlyByProxy permissioned {
340:         
341:         for (uint256 i = 0; i < orders.length; ++i) { // <= FOUND
342:             
343:             _settlePayment(
344:                 orders[i].items,
345:                 orders[i].orderType,
346:                 orders[i].lender,
347:                 orders[i].renter,
348:                 orders[i].startTimestamp,
349:                 orders[i].endTimestamp
350:             );
351:         }
352:     }

```


*GitHub* : [341](https://github.com/re-nft/smart-contracts/tree/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L341-L341) V4 wen?