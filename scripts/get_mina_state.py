import requests
import json
import sys

def query_to_graphql(output_path):
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
    request_res = requests.post("http://localhost:3085/graphql", json={"query": query}).json()
    protocol_state = request_res["data"]["bestChain"][0]
    request_res["data"]["bestChain"] = [protocol_state]
    print("Fetching data for block height: {}".format(protocol_state["protocolState"]["consensusState"]["blockHeight"]))
    return request_res

if __name__ == "__main__":
    output_path = sys.argv[1]
    res = query_to_graphql(output_path)
    with open(output_path, 'w') as f:
        sys.stdout = f  # Change the standard output to the file we created.
        print(json.dumps(res, indent=4))