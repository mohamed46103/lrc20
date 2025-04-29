import { networks } from "bitcoinjs-lib";
import { Lrc20TransactionDto } from "../lrc/types";
import { LRCWallet } from "../lrc/wallet";
import { NetworkType } from "../network";
import { JSONStringify } from "../lrc/utils";
import { instanceToPlain } from "class-transformer";

const LOCKTIME = 150;
const SATOSHIS = 15000;

const wallet = new LRCWallet(
  "4799979d5e417e3d6d00cf89a77d4f3c0354d295810326c6b0bf4b45aedb38f3",
  networks.regtest,
  NetworkType.REGTEST
);

const main = async () => {
  console.log(wallet.p2wpkhAddress);
  console.log(wallet.p2trAddress);

  await wallet.syncWallet();

  const payment = {
    amount: BigInt(20000),
    tokenPubkey: wallet.pubkey.toString("hex"),
    sats: SATOSHIS,
    cltvOutputLocktime: LOCKTIME,
    revocationKey: wallet.pubkey.toString("hex"),
    expiryKey: wallet.pubkey.toString("hex"),
    metadata: {
      token_tx_hash: Buffer.from("7Z1gHgzQmzvVTV6c+GmooasidKFAcwYYSq4qKK+EoC8=", "base64").toString("hex"),
      exit_leaf_index: 1,
    },
  };

  const exitTx = await wallet.prepareSparkExit([payment], 1.0);

  const txDto = Lrc20TransactionDto.fromLrc20Transaction(exitTx);

  console.log(JSONStringify(instanceToPlain(txDto)));

  const result = await wallet.broadcast(txDto);

  console.log(result);
};

main();
