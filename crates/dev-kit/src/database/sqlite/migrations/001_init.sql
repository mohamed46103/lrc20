CREATE TABLE IF NOT EXISTS lrc20_outputs (
       txid TEXT NOT NULL,
       vout INTEGER NOT NULL,

       proof JSONB NOT NULL,
       txout JSONB NOT NULL,

       -- As sqlite has not support for enums
       -- we integers here. Possible values are:
       -- 0 - Unspent (default)
       -- 1 - Spent
       -- 2 - Frozen
       state INTEGER NOT NULL DEFAULT 0,

       PRIMARY KEY (txid, vout)
);

CREATE TABLE IF NOT EXISTS key_value (
    key TEXT NOT NULL,
    value TEXT NOT NULL,

    PRIMARY KEY (key)
);
