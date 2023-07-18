import requests
import json
import sys
import argparse
import base58


def write_output_file(data, output_path):
    with open(output_path, 'w') as f:
        sys.stdout = f
        print(json.dumps(data, indent=4))

def get_ledger_hash(args): 
    query = """
    query MyQuery {
    bestChain {
        protocolState {
        blockchainState {
            stagedLedgerHash
        }
        }
    }
    }
    """
    request_res = requests.post(args.url, json={"query": query}).json()
    ledger_hash = request_res["data"]["bestChain"][0]["protocolState"]["blockchainState"]["stagedLedgerHash"]
    return ledger_hash

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

def decode(s):
    return str(base58.b58decode_int(s) % 2**255)

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
    input_data = [str(acc_data["index"])]
    if (acc_data["zkappState"] is None):
        acc_data["zkappState"] = ['0'] * 8
    for x in acc_data["zkappState"]:
        input_data.append(str(x))
    input_data.append(str(acc_data["balance"]["liquid"]))
    input_data.append(str(acc_data["balance"]["locked"]))
    input_data.append(str(decode(acc_data["balance"]["stateHash"])))
    input_data.append(str(acc_data["leafHash"]))
    input_data.append(str(decode(acc_data["receiptChainHash"])))
    for node in acc_data["merklePath"]:
        if (node["left"] is not None):
            input_data.append(str(node["left"]))
        elif (node["right"] is not None):
            input_data.append(str(node["right"]))
    input["array"] = input_data
    input = [input]
    evm_res = {}
    evm_res["public_key"] = args.address
    evm_res["balance"] = {}
    evm_res["balance"]["liquid"] = acc_data["balance"]["liquid"]
    evm_res["balance"]["locked"] = acc_data["balance"]["locked"]
    evm_res["state"] = ""
    for i in range(0, len(acc_data["zkappState"])):
        evm_res["state"] = evm_res["state"] + "0x" + format(int(acc_data["zkappState"][i]), '064x') + ","
    evm_res["state"] = evm_res["state"][:-1]
    
    ledger_hash = get_ledger_hash(args)
    evm_res["proof_extension"] = ledger_hash

    write_output_file(input, "pm_" + args.output)
    write_output_file(evm_res, args.output)
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

