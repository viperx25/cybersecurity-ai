#!/usr/bin/env bash

for i in $(seq -w 2 90); do wget -c https://csr.lanl.gov/data-fence/1775280922/aixg_QSS-oH4EGpCSwQ0gTxSGTg=unified-host-network-dataset-2017/netflow/netflow_day-$i.bz2; done
for i in $(seq -w 1 90); do wget -c https://csr.lanl.gov/data-fence/1775280922/aixg_QSS-oH4EGpCSwQ0gTxSGTg=unified-host-network-dataset-2017/wls/wls_day-$i.bz2; done
