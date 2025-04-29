#!/bin/sh
sleep 10
echo "Faucet is running"
bitcoin-cli createwallet lrc20-faucet
bitcoin-cli loadwallet lrc20-faucet
while true; do bitcoin-cli -regtest -generate 1; sleep 30; done
