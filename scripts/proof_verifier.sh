#!/bin/bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR
pwd
cd ..
BASEDIR=$(pwd)
PROOF_PATH="${BASEDIR}/share/aux-proof-verify/proof.data"
VERIFIER=${BASEDIR}/share/aux-proof-verify/web3_verify.py
PROOF_FETCHER=${BASEDIR}/share/proof-market/scripts/proof_get_id.py
PROOF_ID="1"
python3 $PROOF_FETCHER $PROOF_ID $PROOF_PATH
