import solcx

from web3 import Web3
from web3.middleware import geth_poa_middleware
import os
import sys
import shutil

base_path = os.path.abspath(os.getcwd())  + '/'
contracts_dir = base_path + 'share/evm-state/contracts'

def init_profiling():
    if "--nolog" in sys.argv:
        print("No logging!")
        shutil.copyfile(contracts_dir+"/profiling_disabled.sol", contracts_dir+"/profiling.sol")
    else:
        shutil.copyfile(contracts_dir+"/profiling_enabled.sol", contracts_dir+"/profiling.sol")

def init_connection():
    w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545', request_kwargs={'timeout': 600}))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    w3.eth.default_account = w3.eth.accounts[0]
    return w3


def find_compiled_contract(compiled, contract_name):
    compiled_id = None
    compiled_interface = False
    for key, value in compiled.items():
        if key.endswith(contract_name):
            compiled_id = key
            compiled_interface = value
            break
    else:
        print(f'{contract_name} not found!')
        exit(1)
    return compiled_id, compiled_interface


def write_tx_calldata(w3, tx_receipt, ofname='tx_calldata.txt'):
    with open(ofname, 'w') as f:
        f.write(w3.eth.get_transaction(tx_receipt.transactionHash).input)


def print_tx_info(w3, tx_receipt, tx_name):
    print(tx_name)
    print(tx_receipt.transactionHash.hex())
    print('gasUsed =', tx_receipt.gasUsed)
    write_tx_calldata(w3, tx_receipt)


def deploy_link_libs(w3, compiled, test_contract_bytecode, linked_libs_names):
    linked_bytecode = test_contract_bytecode
    for lib_name in linked_libs_names:
        compiled_lib_id, component_lib = find_compiled_contract(compiled, lib_name)
        component_lib_bytecode = component_lib['bin']
        component_lib_abi = component_lib['abi']
        print(f'Lib {lib_name} bytecode size:', len(component_lib_bytecode) // 2)
        contract_lib = w3.eth.contract(
            abi=component_lib_abi, bytecode=component_lib_bytecode)
        deploy_lib_tx_hash = contract_lib.constructor().transact()
        deploy_lib_tx_receipt = w3.eth.wait_for_transaction_receipt(deploy_lib_tx_hash)
        linked_bytecode = solcx.link_code(
            linked_bytecode,
            {compiled_lib_id: deploy_lib_tx_receipt.contractAddress},
            solc_version="0.8.17")
    print('Bytecode size:', len(linked_bytecode) // 2)
    return linked_bytecode

profiling_start_block = 0;
profiling_end_block = 1;
profiling_log_message = 2;
profiling_log_decimal = 3;
profiling_log_hexadecimal = 4;

class gas_usage_event:
    def  __init__(self, event):
        self.command = event['args']['command'];
        self.gas_usage = event['args']['gas_usage'];
        self.function_name = event['args']['function_name'];

def print_profiling_log(logs, totalGas, filename):
    f = open(filename, "w")
    stack = [];
    result = [];
    depth = 1;
    prefix = "";
    cur_gas_start = 0;
    for i in range(len(logs)):
        event = logs[i]
        e = gas_usage_event(event)

        if( e.command == profiling_start_block):
            cur_gas_start = e.gas_usage
            e.block_gas_usage = e.gas_usage
            result.append(e)
            stack.append(i)
        if( e.command == profiling_end_block):
            start_ind = stack.pop()
            cur_gas_start = result[start_ind].block_gas_usage
            e.block_gas_usage = cur_gas_start - e.gas_usage
            result.append(e)
            result[start_ind].block_gas_usage = cur_gas_start - e.gas_usage
        if( e.command == profiling_log_message):
            e.block_gas_usage = cur_gas_start - e.gas_usage
            result.append(e)
        if( e.command == profiling_log_decimal):
            e.block_gas_usage = e.gas_usage
            result.append(e)
        if( e.command == profiling_log_hexadecimal):
            e.block_gas_usage = e.gas_usage
            result.append(e)
    first = True
    print("{\"totalGas\":","\"", totalGas, "\",", file = f, sep = "")
    i = 0
    depth = 0
    for e in result:
        gas_usage = e.gas_usage;
        block_gas_usage = e.block_gas_usage
        if( e.command == profiling_start_block ):
            if not first:
                print(",",file = f)
            first = False
            print(prefix, "\"",i,"_",e.function_name,'\":{', file = f, sep = "")
            depth += 1
            prefix = "    " * depth
            print(prefix,"\"gas_usage\":\"",block_gas_usage, "\"", file = f, end = "", sep = "")
        if( e.command == profiling_end_block ):
            first = False
            depth -=1
            prefix = "    " * depth
            print("", file=f)
            print(prefix, "}", file = f, end="")   
        if( e.command == profiling_log_message ):
            if not first:
                print(",", file = f)
            print(prefix, "\"",i,"_message\":\"",e.function_name, "\"", file = f,  end="", sep="")   
            first = False
        if( e.command == profiling_log_decimal):
            if not first:
                print(",", file = f)
            print(prefix, "\"",i,"_",e.function_name, "\":\"", block_gas_usage,"\"", file = f,  end="", sep="")   
            first = False
        if( e.command == profiling_log_hexadecimal):
            if not first:
                print(",", file = f)
            print(prefix, "\"",i,"_",e.function_name, "\":\"", hex(block_gas_usage),"\"", file = f,  end="", sep="")   
            first = False
        i = i + 1;
    print("", file = f)
    print("}", file = f)

def do_placeholder_verification_test_via_transact_simple(test_contract_name, test_contract_path, linked_libs_names,
                                                         init_test_params_func):
    init_profiling()
    w3 = init_connection()
    solcx.install_solc('0.8.17')
    print(f'{contracts_dir}/{test_contract_path}')
    compiled = solcx.compile_files(
        [f'{contracts_dir}/{test_contract_path}'],
        allow_paths=[f'{contracts_dir}/'],
        output_values=['abi', 'bin'],
        solc_version="0.8.17",
        optimize=True,
        optimize_runs=200)
    compiled_test_contract_id, compiled_test_contract_interface = find_compiled_contract(
        compiled, test_contract_name)
    bytecode = compiled_test_contract_interface['bin']
    abi = compiled_test_contract_interface['abi']
    bytecode = deploy_link_libs(w3, compiled, bytecode, linked_libs_names)

    test_contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    deploy_tx_hash = test_contract.constructor().transact()
    deploy_tx_receipt = w3.eth.wait_for_transaction_receipt(deploy_tx_hash)
    print("Deployment:", deploy_tx_receipt.gasUsed)

    test_contract_inst = w3.eth.contract(
        address=deploy_tx_receipt.contractAddress, abi=abi)
    params = init_test_params_func()
    run_tx_hash = test_contract_inst.functions.verify(
        params['proof'], params['init_params'], params['columns_rotations']).transact()
    run_tx_receipt = w3.eth.wait_for_transaction_receipt(run_tx_hash)
    print_tx_info(w3, run_tx_receipt, params['_test_name'])

    if "--nolog" not in sys.argv:
        if hasattr(test_contract_inst.events, "gas_usage_emit"):
            logfilename = "logs/log.json"
            if "log_file" in params.keys():
                logfilename = params["log_file"]
            logfilename = base_path + logfilename
            print("Print log in ", logfilename)
            print_profiling_log(test_contract_inst.events.gas_usage_emit.getLogs(), run_tx_receipt.gasUsed, logfilename)
        else:
            print("No logging events in solidity abi")
    else:
        print("Logging disabled")