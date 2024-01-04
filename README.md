# reNFT audit details

- Total Prize Pool:$83,600 in USDC
  - HM awards: $41,250 in USDC
  - Analysis awards: $2,500 in USDC
  - QA awards: $1,250 in USDC
  - Bot Race awards: $3,750 in USDC
  - Gas awards: $1,250 in USDC
  - Judge awards: $9,300 in USDC
  - Lookout awards: $4,000 in USDC
  - Scout awards: $500 in USDC
  - Mitigation Review: $19,800 in USDC (_Opportunity goes to top 3 certified
    wardens based on placement in this audit._)
- Join [C4 Discord](https://discord.gg/code4rena) to register
- Submit findings
  [using the C4 form](https://code4rena.com/contests/2024-01-renft/submit)
- [Read our guidelines for more details](https://docs.code4rena.com/roles/wardens)
- Starts January 8, 2024 20:00 UTC
- Ends January 18, 2024 20:00 UTC

### ❗ The code for this contest is located in a separate [repo](https://github.com/re-nft/smart-contracts/commit/fc5cc6d408f5cc77b817809b0b93adfa4ced2fdd).

## Automated Findings / Publicly Known Issues

### Automated Findings

The 4naly3er report can be found
[here](https://github.com/code-423n4/2024-01-renft/blob/main/4naly3er-report.md).

Automated findings output for the audit can be found
[here](https://github.com/code-423n4/2024-01-renft/blob/main/bot-report.md)
within 24 hours of audit opening.

_Note for C4 wardens: Anything included in this
`Automated Findings / Publicly Known Issues` section is considered a publicly
known issue and is ineligible for awards._

### Publicly Known Issues

#### Manipulation via Hook Contracts

Hook contracts are middleware that execute arbitrary logic before the
transaction payload originating from a rental safe executes at an intended
target address. As such, this leaves plenty of space for unintended behavior if
a malicious or faulty hook contract is used.

This protocol relies on a whitelist which only enables permissioned hook
contracts to interact as middleware within the protocol. Therefore, any exploits
carried out via logic within a custom hook contract are considered to be known
issues.

#### Dishonest ERC721/ERC1155 Implementations

The
[Guard](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Guard.sol)
contract can only protect against the transfer of tokens that faithfully
implement the ERC721/ERC1155 spec. A dishonest implementation that adds an
additional function to transfer the token to another wallet cannot be prevented
by the protocol. Therefore, these issues are considered to be known.

#### Rebasing or Fee-On-Transfer ERC20 Implementations

The protocol contracts do not expect to be interacting with any ERC20 token
balances that can change during transfer due to a fee, or change balance while
owned by the
[PaymentEscrow](https://github.com/re-nft/smart-contracts/blob/main/src/modules/PaymentEscrow.sol)
contract. Therefore, these issues are considered to be known.

# Overview

This protocol facilitates generalized collateral-free rentals built on top of
Gnosis Safe and Seaport.

To give an example, imagine Alice has gaming NFTs. She signs seaport order
typed data and thus signals that she is happy to lend out these assets. Now, Bob
would love to use the NFTs in the game. He finds Alice's listing and rents. This
is where these contracts come into force. A gnosis safe is created for Bob where
assets he rented get sent to. There is a gnosis module that disallows Bob to
move out the assets from his smart contract wallet. He is now free to use the
NFTs in-game.

The [Default Framework](https://github.com/fullyallocated/Default) is used as
the main architecture for the protocol, and the contracts in scope can be
categorized into four main groups:

### Modules

Modules are internal-facing contracts that store shared state across the
protocol. For more information on modules, see
[here](https://github.com/fullyallocated/Default#the-default-framework).

- [Payment Escrow](https://github.com/re-nft/smart-contracts/blob/main/src/modules/PaymentEscrow.sol):
  Module dedicated to escrowing rental payments while rentals are active. When
  rentals are stopped, this module will determine payouts to all parties and a
  fee will be reserved to be withdrawn later by a protocol admin.
- [Storage](https://github.com/re-nft/smart-contracts/blob/main/src/modules/Storage.sol):
  Module dedicated to maintaining all the storage for the protocol. Includes
  storage for active rentals, deployed rental safes, hooks, and whitelists.

### Policies

Policies are external-facing contracts that receive inbound calls to the
protocol, and route all the necessary updates to data models via Modules. For
more information on policies, see
[here](https://github.com/fullyallocated/Default#the-default-framework).

- [Admin](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Admin.sol):
  Acts as an interface for all behavior in the protocol related admin logic.
  Admin duties include fee management, proxy management, and whitelist
  management.
- [Create](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Create.sol):
  Acts as an interface for all behavior related to creating a rental. This is
  the entrypoint for creating a rental through the protocol, which only Seaport
  contracts can access.
- [Factory](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Factory.sol):
  Acts as an interface for all behavior related to deploying rental safes.
  Deploys rental safes using gnosis safe factory contracts.
- [Guard](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Guard.sol):
  Acts as an interface for all behavior related to guarding transactions that
  originate from a rental wallet. Prevents transfers of ERC721 and ERC1155
  tokens while a rental is active, as well as preventing token approvals and
  enabling of non-whitelisted gnosis safe modules
- [Stop](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Stop.sol):
  Acts as an interface for all behavior related to stoping a rental. This policy
  is also a module enabled on all rental safe wallets, and has the authority to
  pull funds out of a rental wallet if a rental is being stopped.

### Packages

Packages are small, helper contracts dedicated to performing a single task which
are imported by other core contracts in the protocol.

- [Accumulator](https://github.com/re-nft/smart-contracts/blob/main/src/packages/Accumulator.sol):
  Package that implements functionality for managing dynamically allocated data
  struct arrays directly in memory. The rationale for this was the need for an
  array of structs where the total size is not known at instantiation.
- [Reclaimer](https://github.com/re-nft/smart-contracts/blob/main/src/packages/Reclaimer.sol):
  Retrieves rented assets from a wallet contract once a rental has been stopped,
  and transfers them to the proper recipient. A delegate call from the safe to
  the reclaimer is made to pull the assets.
- [Signer](https://github.com/re-nft/smart-contracts/blob/main/src/packages/Signer.sol):
  Contains logic related to signed payloads and signature verification when
  creating rentals.

### General

These are general-purpose contracts which are agnostic to the core functionality
of the protocol.

- [Create2 Deployer](https://github.com/re-nft/smart-contracts/blob/main/src/Create2Deployer.sol):
  Deployment contract that uses the init code and a salt to perform a
  deployment. There is added cross-chain safety as well because a particular
  salt can only be used if the sender's address is contained within that salt.
  This prevents a contract on one chain from being deployed by a non-admin
  account on another chain.
- [Kernel](https://github.com/re-nft/smart-contracts/blob/main/src/Kernel.sol):
  A registry contract that manages a set of policy and module contracts, as well
  as the permissions to interact with those contracts. Privileged admin and
  executor roles exist to allow for role-granting and execution of kernel
  functionality which includes adding new policies or upgrading modules.

## Links

- **Previous audits:** there were no previous audits
- **Documentation:** there is no documentation outside of this readme and the
  actual code repo
- **Website:** https://renft.io
- **Twitter:** https://twitter.com/renftlabs
- **Discord:** https://discord.gg/4Ab8tknmhf

## Contact Information

| Contact | Discord  | Telegram                                      | Twitter                                              |
| ------- | -------- | --------------------------------------------- | ---------------------------------------------------- |
| Naz     | nazariyv | [nazariyv](https://t.me/nazariyv)             | [AlgorithmicBot](https://twitter.com/AlgorithmicBot) |
| Alec    | Alec1017 | [alecdifederico](https://t.me/alecdifederico) | [alecdifederico](https://twitter.com/alecdifederico) |

# Scope

| Contract                                                                                                           | SLOC | Purpose                                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------ | ---- | ----------------------------------------------------------------------------------------------------------------------------------- |
| [src/modules/PaymentEscrow.sol](https://github.com/re-nft/smart-contracts/blob/main/src/modules/PaymentEscrow.sol) | 156  | Escrows rental payments while rentals are active.                                                                                   |
| [src/modules/Storage.sol](https://github.com/re-nft/smart-contracts/blob/main/src/modules/Storage.sol)             | 106  | Maintains all the storage for the protocol.                                                                                         |
| [src/packages/Accumulator.sol](https://github.com/re-nft/smart-contracts/blob/main/src/packages/Accumulator.sol)   | 46   | Implements functionality for managing dynamically allocated data struct arrays directly in memory.                                  |
| [src/packages/Reclaimer.sol](https://github.com/re-nft/smart-contracts/blob/main/src/packages/Reclaimer.sol)       | 41   | Retrieves rented assets from a wallet contract once a rental has been stopped, and transfers them to the proper recipient.          |
| [src/packages/Signer.sol](https://github.com/re-nft/smart-contracts/blob/main/src/packages/Signer.sol)             | 195  | Contains logic related to signed payloads and signature verification when creating rentals.                                         |
| [src/policies/Admin.sol](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Admin.sol)               | 58   | Admin duties include fee management, proxy management, and whitelist management.                                                    |
| [src/policies/Create.sol](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Create.sol)             | 365  | Acts as an interface for all behavior related to creating a rental.                                                                 |
| [src/policies/Factory.sol](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Factory.sol)           | 78   | Acts as an interface for all behavior related to deploying rental safes.                                                            |
| [src/policies/Guard.sol](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Guard.sol)               | 161  | Acts as an interface for all behavior related to guarding transactions that originate from a rental wallet.                         |
| [src/policies/Stop.sol](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Stop.sol)                 | 162  | Acts as an interface for all behavior related to stoping a rental.                                                                  |
| [src/Create2Deployer.sol](https://github.com/re-nft/smart-contracts/blob/main/src/Create2Deployer.sol)             | 44   | Deployment contract that uses the init code and a salt to perform a deployment.                                                     |
| [src/Kernel.sol](https://github.com/re-nft/smart-contracts/blob/main/src/Kernel.sol)                               | 251  | A registry contract that manages a set of policy and module contracts, as well as the permissions to interact with those contracts. |

## Out of scope

- [examples/\*](https://github.com/re-nft/smart-contracts/tree/main/src/examples)
- [interfaces/\*](https://github.com/re-nft/smart-contracts/tree/main/src/interfaces)
- [libraries/\*](https://github.com/re-nft/smart-contracts/tree/main/src/libraries)
- [proxy/\*](https://github.com/re-nft/smart-contracts/tree/main/src/proxy)
- [packages/Zone.sol](https://github.com/re-nft/smart-contracts/blob/main/src/packages/Zone.sol)

# Additional Context

### ERC20 Token Support

Fee on transfer and rebasing ERC20 tokens are not supported

All ERC20 tokens supported by Seaport are supported here. (!Alec)

### ERC721/ERC1155 Token Support

There are no restrictions placed on what 721/1155 tokens protocol can interact
with. Similarly to ERC20 token support, all tokens supported by Seaport are
supported here. (!Alec)

### Deployed Blockchains

Which blockchains will this code be deployed to, and are considered in scope for
this audit?

We are going to launch on: Ethereum Mainnet, Polygon and Avalanche to begin
with. We will then look to expand to all the chains that are supported by Safe.

### Trusted Roles

- `SEAPORT`: Addresses granted this role will be allowed to interact with the
  `validateOrder()` function in the Create Policy. This is a singleton role that
  should only be granted to the Seaport core contract.
- `CREATE_SIGNER`: Addresses granted this role are considered protocol signers
  which can sign off on payloads wishing to initiate a rental.
- `ADMIN_ADMIN`: Addresses granted this role are considered admins of the Admin
  Policy, and can conduct admin operations on the protocol.
- `GUARD_ADMIN`: Addresses granted this role can toggle whitelisted hook
  contracts and which addresses are safe for a rental wallet to delegate call

Additional descriptions of protocol behavior can be found
[here](https://github.com/code-423n4/2024-01-renft/tree/main/docs).

## Attack ideas (Where to look for bugs)

### Rental Wallet Security

One of the hallmarks of the protocol is that users should be able to safely rent
out their assets to rental wallets. These rental wallets should not be allowed
to move these assets freely. Potential attack surfaces include usage of delegate
call, use of a prohobited function selector, use of a prohibited gnosis safe
module, or inability for the protocol to retrieve the asset from the rental
wallet once the rental has expired.

### Proper Rental Creation

Rentals are first transferred to the rental wallet during the processing of a
seaport order. Afterwards, a rental is handled by this protocol and logged in
storage. A potential attack vector is the prevention of storing the identifier
of the rental in storage. If the protocol doesnt know the rental exists, then
there is no way to keep the asset in the rental wallet.

### Proper Rental Stopping

Once a rental has expired, any address can initiate the reclaiming process to
give rented assets back to the lender, and payments to their intended
recipients. A potential attack vector is the breaking of these invariants where
lenders may not receive their expected assets back, or payments (denominated in
ERC20 tokens) are not given to the proper addresses or in the correct amounts.

## Main invariants

- Recipient of ERC721 / ERC1155 tokens after rental creation is always the reNFT
  smart contract renter
- Recipient of ERC721 / ERC1155 tokens after rental stop is always the original
  owner of the asset wallet
- Recipient of ERC20 tokens after rental creation is always the Payment Escrow
  Module
- Recipient of ERC20 tokens after rental stop is always the lender address if
  the rental was a BASE order and is the renter address if the rental was a PAY
  order
- Stored token balance of the
  [Payment Escrow](https://github.com/re-nft/smart-contracts/blob/main/src/modules/PaymentEscrow.sol)
  contract should never be less than the true token balance of the contract
- Rental safes can never make a call to `setGuard()`
- Rental safes can never make a call to `enableModule()` or `disableModule()`
  unless the target has been whitelisted by the
  [Admin Policy](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Admin.sol)
- Rental safes can never make a delegatecall unless the target has been
  whitelisted by the
  [Admin Policy](https://github.com/re-nft/smart-contracts/blob/main/src/policies/Admin.sol)
- ERC721 / ERC1155 tokens cannot leave a rental wallet via `approve()`,
  `setApprovalForAll()`, `safeTransferFrom()`, `transferFrom()`, or
  `safeBatchTransferFrom()`
- Hooks can only be specified for ERC721 and ERC1155 items
- Only one hook can act as middleware to a target contract at one time. But,
  there is no limit on the amount of hooks that can execute during rental start
  or stop.
- When control flow is passed to hook contracts, the rental concerning the hook
  will be active and a record of it will be stored in the
  [Storage Module](https://github.com/re-nft/smart-contracts/blob/main/src/modules/Storage.sol)

## Scoping Details

- If you have a public code repo, please share it here:
  https://github.com/re-nft/smart-contracts/commit/fc5cc6d408f5cc77b817809b0b93adfa4ced2fdd
- How many contracts are in scope?: 17
- Total SLoC for these contracts?: 1600
- How many external imports are there?: 2
- How many separate interfaces and struct definitions are there for the
  contracts within scope?: 4 interfaces 11 struct
- Does most of your code generally use composition or inheritance?: Composition
- How many external calls?: 6
- What is the overall line coverage percentage provided by your tests?: 80
- Is this an upgrade of an existing system?: False
- Check all that apply (e.g. timelock, NFT, AMM, ERC20, rollups, etc.): NFT
- Is there a need to understand a separate part of the codebase / get context in
  order to audit this part of the protocol?: True
- Please describe required context: Knowledge of Seaport and Gnosis Safe smart
  contracts
- Does it use an oracle?: No
- Describe any novel or unique curve logic or mathematical models your code
  uses: None
- Is this either a fork of or an alternate implementation of another project?:
  False
- Does it use a side-chain?: No
- Describe any specific areas you would like addressed: see **Attack Ideas**
  above

# Tests

This protocol uses
[Foundry](https://book.getfoundry.sh/getting-started/installation) to run tests.
To get started:

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Install all dependencies:

```bash
forge install
```

Run tests:

```bash
forge test
```

Run tests with a gas report:

```bash
forge test --gas-report
```

> If forge fails to run, please confirm you are running the latest version. This
> was tested with forge `0.2.0`.

# Slither Notes

Make sure slither is installed:

```
pip3 install slither-analyzer
```

To run static analysis on the contracts:

```
slither .
```

We have run default detectors with Slither and posted the output along with our
[responses](https://github.com/code-423n4/2024-01-renft/blob/main/docs/slither.md)
to each. Please do not submit these findings unless you have reason to believe
our responses here are not valid.

> Low severity detectors are not provided, and neither are their explicit
> justifications
