import requests
import json
import sys
import argparse
import base58


def get_mina_ledger_state(args):
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
    request_res = requests.post(args.url, json={"query": query}).json()
    protocol_state = request_res["data"]["bestChain"][0]
    request_res["data"]["bestChain"] = [protocol_state]
    print("Fetching data for block height: {}".format(protocol_state["protocolState"]["consensusState"]["blockHeight"]))
    print("Hash: {}".format(protocol_state["protocolState"]["blockchainState"]["snarkedLedgerHash"]))
    write_output_file(request_res, args.output)
    return



def write_output_file(data, output_path):
    with open(output_path, 'w') as f:
        sys.stdout = f
        print(json.dumps(data, indent=4))

def decode(s):
    return str(base58.b58decode_int(s))

def get_mina_account_state(args):
    query = '''
    query {{
      account(publicKey: "{0}" ) {{
        index
        zkappState
        balance {{
          liquid
          locked
          stateHash
        }}    
        leafHash
        receiptChainHash
        merklePath {{
          left,
          right
        }}
      }}
    }}
    '''.format(args.address)
    request_res = requests.post(args.url, json={"query": query}).json()
    input = {}
    acc_data = request_res["data"]["account"]
    input_str = str(acc_data["index"]) + "\n"
    if (acc_data["zkappState"] is None):
        for _ in range(0, 8):
            input_str += "0\n"
    else:
        for x in acc_data["zkappState"]:
            input_str += str(x) + "\n"
    input_str += acc_data["balance"]["liquid"] + "\n"
    input_str += acc_data["balance"]["locked"] + "\n"
    input_str += decode(acc_data["balance"]["stateHash"])+ "\n"
    input_str += acc_data["leafHash"] + "\n"
    input_str += decode(acc_data["receiptChainHash"]) + "\n"
    for node in acc_data["merklePath"]:
        if (node["left"] is not None):
            input_str += node["left"] + "\n"
        elif (node["right"] is not None):
            input_str += node["right"] + "\n"
    input["input"] = input_str
    write_output_file(input, args.output)
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='Mina Helper for =nil; Proof Market',
        description='Mina Helper retrieves data related to Proof Market functionality from Mina node')
    parser.add_argument('--url', help="GraphQL URL", default="https://proxy.berkeley.minaexplorer.com/")
    parser.add_argument('--output', help="Output file path", default="output.json")

    subparsers = parser.add_subparsers(help="sub-command help")
    parser_ledger = subparsers.add_parser("ledger", help="Fetch mina ledger state")
    parser_ledger.set_defaults(func=get_mina_ledger_state)

    parser_account = subparsers.add_parser("account", help="Fetch mina zkApp/user state")
    parser_account.add_argument('--address', help="Mina public key of zkApp or user", default="", required=True)
    parser_account.set_defaults(func=get_mina_account_state)

    args = parser.parse_args()
    args.func(args)

