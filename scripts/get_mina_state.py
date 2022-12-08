import requests
import json
import sys
import argparse

def state_query_to_graphql(output_path, url):
    query = """
    query MyQuery {
    blockchainVerificationKey
    bestChain {
        protocolStateProof {
        json
        }
        protocolState {
        previousStateHash
        consensusState {
            blockHeight
            blockchainLength
            epoch
            epochCount
            hasAncestorInSameCheckpointWindow
            lastVrfOutput
            minWindowDensity
            nextEpochData {
            epochLength
            ledger {
                hash
                totalCurrency
            }
            lockCheckpoint
            seed
            startCheckpoint
            }
            slot
            slotSinceGenesis
            totalCurrency
            stakingEpochData {
            epochLength
            ledger {
                hash
                totalCurrency
            }
            lockCheckpoint
            seed
            startCheckpoint
            }
        }
        blockchainState {
            date
            snarkedLedgerHash
            stagedLedgerHash
            stagedLedgerProofEmitted
            utcDate
        }
        }
    }
    }
    """
    request_res = requests.post(url, json={"query": query}).json()
    protocol_state = request_res["data"]["bestChain"][0]
    request_res["data"]["bestChain"] = [protocol_state]
    print("Fetching data for block height: {}".format(protocol_state["protocolState"]["consensusState"]["blockHeight"]))
    print("Hash: {}".format(protocol_state["protocolState"]["blockchainState"]["snarkedLedgerHash"]))
    return request_res

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    prog = 'Mina Helper for =nil; Proof Market',
                    description = 'Mina Helper retrieves data related to Proof Market functionality from Mina node')
    parser.add_argument('--url', help="GraphQL URL", default="http://localhost:3085/graphql")
    parser.add_argument('--output', help="Output file path", default="proof_market_data.json")
    args = parser.parse_args()
    url = args.url
    output_path = args.output
    res = state_query_to_graphql(output_path, url)
    with open(output_path, 'w') as f:
        sys.stdout = f  # Change the standard output to the file we created.
        print(json.dumps(res, indent=4))