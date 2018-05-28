#!/bin/bash
HOST=`hostname`
THREADS=`lspci | grep -c "1d0f:1041"`
AGFI=`/usr/bin/curl -f -s -S -k https://sense-it.co/current_agfi.html`
POOL=`/usr/bin/curl -f -s -S -k https://sense-it.co/current_pool.html`
ALGO=`/usr/bin/curl -f -s -S -k https://sense-it.co/current_algo.html`
C=0

while [ $C -lt $THREADS ]
do
        /usr/local/bin/fpga-load-local-image -S $C -I $AGFI
        (( C++ ))
done

sleep 30
screen -dmS mine ./fpga_miner -a $ALGO -t $THREADS -o stratum+tcp://$POOL -u 1PWeGEhgZewUB5hmuzygMzj1EG4Bt6Q7PR.${HOST//.} -p x -s 2
