#!/bin/bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR
cd ..
BASEDIR=$(pwd)
PROOF_PATH="${BASEDIR}/share/aux-proof-verify/loaded_proof.data"
ADDRESS_PATH="${BASEDIR}/share/aux-proof-verify/address.data"
VERIFIER=${BASEDIR}/share/aux-proof-verify/web3_verify.py
DEPLOY=${BASEDIR}/share/aux-proof-verify/web3_deploy.py
PROOF_FETCHER=${BASEDIR}/share/proof-market/proof_get_id.py
PROOF_ID="8"
echo getting proof...
python3 $PROOF_FETCHER $PROOF_ID $PROOF_PATH
echo deploy...
python3 $DEPLOY $ADDRESS_PATH
ADDRESS_VALUE=$(<$ADDRESS_PATH)
echo $ADDRESS_VALUE
echo verify...
python3 $VERIFIER $ADDRESS_VALUE $PROOF_PATH