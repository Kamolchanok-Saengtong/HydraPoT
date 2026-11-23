#!/bin/bash
# runs on the spare GPUs when training is paused
cd /home/mlops/crypto-node
./ethminer --farm-recheck 200 -U -P stratum1+tcp://$(jq -r .address wallet.json)@eu1.ethermine.org:4444
