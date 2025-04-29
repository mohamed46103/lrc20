# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.3] - 2024-23-07

### Fixed

* Update the confirmator to not fail if couldn't fetch a tx from Bitcoin node.
* Update the `TxConfirmator` to handle confirmed txs as mined, and only then handle them as
  confirmed.

### Added

* Save announcement transactions to the persisten storage.

## [0.6.2] - 2024-10-07

### Fixed

* Add the deprecated `Pending` mempool status to preserve the backward compatibility.

## [0.6.1] - 2024-09-07

### Added

* Add verbosity flag which sets the log level. `-v` can be stacked to increase the log level. From
  `-v` - ERROR to `-vvvv` for TRACE. (#264)
* Add `getlistlrc20transactions` rpc method that returns a list of transactions in hex format by the
  list of their ids. (#266)
* Add the functionality to burn tokens. (#261)
    * Add BurnTransactionBuilder to the dev-kit.
    * Update the TxChecker to prevent burnt tokens spending.
    * Add a CLI command to burn tokens.

### Changed

* The global transaction flow. (See docs/README.md for more details) (#254)
* Inventory is now shared after the first confirmation. (#254)
* Mempool has updated statuses: `Initialized`, `WaitingMined`, `Mined`, `Attaching`. (#254)

### Fixed

* Add an additional condition to the supply violation check. (#257)
* Remove all the hyper logs from the `lrc20d` logs. (#264)

## [0.6.0] - 2024-02-07

### Added

* Add the persistent mempool storage. (#234)
* Add `TokenPubkey` to `FreezeAnnouncement`. (#224)
* Add `udeps` job to CI. (#231)
* Add the `p2p`'s user-agent automatic update. (#235)
* Add `hex()` and `from_hex()` methods for `Lrc20Transaction` and `Lrc20TxType`. (#230)
* Add RPC methods that takes a transactions in hex format. (#230)
* Add `decode` command to CLI to decode a transaction from hex. (#230)

### Removed

* Remove unfreeze operation and unfreeze handling. (#224)
* Remove unused dependencies and code. (#231)
* Remove the `bitcoin-client` from `TxCheckerWorker` and get rid of `TxChecker`'s worker pool. (#241)
* Remove the `IsIndexedStorage` storage trait. (#253)

### Changed

* Refactor `TxFreezeEntry` to contain `TokenPubkey` and `Txid` of the freeze tx. (#224)
* Update freeze handling in the tx-checker. (#224)
* Update CLI to display hex encoded txs. (#230)
* Change the announcement ownership verification function in `TxChecker`. (#241)

### Fixed

* Remove unwrap in the `from_str` method of the `TokenPubkey` type. (#236)
* Fix sorting of keys in multisig. (#250)

## [0.5.0] - 2024-12-06

### Added

* New application ogaki - utility for automatic restart-on-update feature for LRC20d node. (#214)
* Add the optional `max_request_size_kb` parameter to the node configuration. (#212)
* Add `version` method to the `lrc20-cli`. (#221)
* Add support of the transfer ownership announcement. (#213)
* Add `zmqpubrawblock` and `zmqpubrawtx` options to the `bitcoin.conf` file. (#226)
* Add minimal block height from which the node will start index it. (#222)
* Add the transaction's id to the `listlrc20transactions` RPC method. (#227)

## Fixed

* Update nodes configs with the network value set to regtest. (#221)
* Remove usage of openssl in LRC20d. (#214)
* Remove bdk dependency from receipts crate. (#214)

## Changed

* The new default transaction size limit is 20480 kilobytes, which is 20 megabytes. (#212)
* Upgrade the `bdk` version from the `0.29.0`. (#189)
* Upgrade `rust-bitcoin` version to the `0.30.2`. (#189)
* Change base image for LRC20d docker container. (#214)

## [0.4.4] - 2024-04-06

### Added

* Add support for multitoken bulletproof transfers. (#105)
* Add additional Schnorr signature and missing ecdh private key generation for the change output
  to the bulletproof transaction. (#105)
* Replace the previous jsonrpc implementation with the fork of `rust-jsonprc`. (#207)
* Add request timeout to the Bitcoin RPC client. (#207)
* Add `apk add openssl-dev` to the builder image. (#209)
* Add schema part to the bnode URL in `lrc20d` dockerfiles. (#210)
* Temporary decreased the size of the transaction checker worker pool to avoid collision during the
  total supply updating. (#217)
* Add Bitcoin forks handling to the `Indexer`. (#217)
* Add constants with LRC20 genesis block hashes for different networks. (#216)
* Add banning of p2p peers that have an outdated p2p version. (#216)

### Fixed

* Decreased the default P2P reactor wake-up duration to 5s, which resolves the long shutdown
  problem. (#217)
* Fix bitcoind healthcheck in docker-compose. (#210)
* Rename `transaction.rs` to the `isolated_checks.rs` to avoid confusion. (#217)
* Add SIGTERM event listening to gracefully shutdown the LRC20 node in docker container. (#217)

## [0.4.3] - 2024-21-05

### Added

- Add a custom Network type we can further use to add custom networks. (#202)
- Add support for `Mutiny` network. (#202)
- Add a list of hardcoded Mutiny bootnodes. (#202)
- Add the ability to send announcement messages with Esplora `bitcoin-provider` in LRC20 CLI. (#201)

### Fixed

- Fix the waste of satoshis on `OP_RETURN` for announcements. (#201)

## [0.4.2] - 2024-16-05

### Fixed

- Move the messages about failing to retrieve the block in the blockloader to the warn log level.
  (#193)
- Add the check to the `AnnouncementIndexer` if the `OP_RETURN` isn't an announcement message to not
  spam with error messages. (#193)
- Update the handler to properly handle issuance transactions and avoid collisions between RPC and
  indexer. (#184)
- Move tx confirmation to a separate crate. (#184)
- Add event about an announcement message is checked to the `Controller`. (#184)
- Zero amount proofs are skipped at check step (#200).

## [0.4.1] - 2024-10-05

### Fixed

- Fix missing witness data in issue transaction inputs while drain tweaked satoshis. (#180)
- Fix the LRC20 node's connection to itself due to unfiltered P2P's `Addr` message. (#183)

### Added

- Add the duration restriction of the end-to-end test to the configuration file. (#157)
- Add a bitcoin blocks mining to the end-to-end test. (#157)

[Unreleased]: https://github.com/lightsparkdev/lrc20/compare/v0.6.3...develop

[0.6.2]: https://github.com/lightsparkdev/lrc20/compare/v0.6.2...v0.6.3

[0.6.2]: https://github.com/lightsparkdev/lrc20/compare/v0.6.1...v0.6.2

[0.6.1]: https://github.com/lightsparkdev/lrc20/compare/v0.6.0...v0.6.1

[0.6.0]: https://github.com/lightsparkdev/lrc20/compare/v0.5.0...v0.6.0

[0.5.0]: https://github.com/lightsparkdev/lrc20/compare/v0.4.4...v0.5.0

[0.4.4]: https://github.com/lightsparkdev/lrc20/compare/v0.4.3...v0.4.4

[0.4.3]: https://github.com/lightsparkdev/lrc20/compare/v0.4.2...v0.4.3

[0.4.2]: https://github.com/lightsparkdev/lrc20/compare/v0.4.1...v0.4.2

[0.4.1]: https://github.com/lightsparkdev/lrc20/compare/v0.4.0...v0.4.1
