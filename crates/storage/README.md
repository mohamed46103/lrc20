# `lrc20-storage`

Provides traits and implementations of storage for LRC20 transactions. For default
use case it is a wrapper around `LevelDB` database, for tests - in-memory storage.

All the types that come through the storage are serialized using `ciborium`.
