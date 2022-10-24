#!/bin/bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR
pwd
cd ..
pwd
BASEDIR=$(pwd)
STATE_PATH="${BASEDIR}/bin/aux-proof-gen/src/data/mina_state.json"
echo order is matched
echo fetching current mina state
(cd $SCRIPT_DIR && python get_mina_state.py $STATE_PATH)
echo 'generating proof (it takes a while...)'
(cd ${BASEDIR}/build/bin/aux-proof-gen/ && ./aux-proof-gen --vp_input=${BASEDIR}/bin/aux-proof-gen/src/data/kimchi.json --vi_input=${BASEDIR}/bin/aux-proof-gen/src/data/kimchi.json --vi_const_input=${BASEDIR}/bin/aux-proof-gen/src/data/kimchi_const.json --output=${BASEDIR}/bin/aux-proof-gen/src/data/proof  --scalar_proof --max_step=1)
