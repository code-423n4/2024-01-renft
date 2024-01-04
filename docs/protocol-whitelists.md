## Protocol Whitelists

### Overview

There are two main whitelists maintained by the protocol. The first is a whitelist for the gnosis safe modules which can be added to a rental safe, and the second a whitelist for which addresses are safe for a rental wallet to use delegate call with. 

### Module Whitelist

During a call to a contract from a rental safe, the [Guard Policy](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Guard.sol) will check the function selector see if a call is made to either enable or disable a gnosis safe module. 

This check is important because a malicious operator of a rental safe could enable a module that can just withdraw all rented assets directly out of the safe, which would completely bypass the guard.

By default, all rental safe are created with the [Stop Policy](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol) enabled as a gnosis safe module. This allows the policy to directly reclaim all assets from the rental safe after an order has expired.  

### Delegate Call Whitelist

During a call to a contract from a rental safe, the operator can specify whether the call should be a normal call or a delegate call. 

The target of the delegate call is important to whitelist because a malicious operator could delegate call into a contract which contains logic that could withdraw all rented assets from the safe. Again, this completely bypasses the guard. 

However, the controlled use of delegate call is a good thing. For example, the only way for a safe owner to upgrade the [Stop Policy](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol) is to disable it as a module and enable a new one. But, by default the protocol disallows safe owners from doing that. So to fix this, we can deploy a separate contract which is whitelisted for delegate call which can perform the disable and enable all in one swoop. An example of this can be found [here](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/examples/upgrades/StopPolicyUpgrade.sol).