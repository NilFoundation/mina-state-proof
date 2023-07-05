import {task} from "hardhat/config";
import fs from "fs";
import path from "path";
import losslessJSON from "lossless-json";

function getFileContents(filePath) {
    return fs.readFileSync(filePath, 'utf8');
}

function loadParamsFromFile(jsonFile) {
    let named_params: any = {};
    named_params = losslessJSON.parse(fs.readFileSync(jsonFile, 'utf8'));
    let params: { [key: string]: any } = {};
    params['init_params'] = [];
    params['init_params'].push(BigInt(named_params.modulus));
    params['init_params'].push(BigInt(named_params.r));
    params['init_params'].push(BigInt(named_params.max_degree));
    params['init_params'].push(BigInt(named_params.lambda));
    params['init_params'].push(BigInt(named_params.rows_amount));
    params['init_params'].push(BigInt(named_params.omega));
    params['init_params'].push(BigInt(named_params.D_omegas.length));
    for (let i in named_params.D_omegas) {
        params['init_params'].push(BigInt(named_params.D_omegas[i]))
    }
    params['init_params'].push(BigInt(named_params.step_list.length));
    for (let i in named_params.step_list) {
        params['init_params'].push(BigInt(named_params.step_list[i].value))
    }
    params['init_params'].push(BigInt(named_params.arithmetization_params.length));
    for (let i in named_params.arithmetization_params) {
        params['init_params'].push(BigInt(named_params.arithmetization_params[i].value))
    }

    params['columns_rotations'] = [];
    for (let i in named_params.columns_rotations) {
        let r : any = [];
        for (let j in named_params.columns_rotations[i]) {
            r.push(BigInt(named_params.columns_rotations[i][j].value));
        }
        params['columns_rotations'].push(r);
    }
    return params;
}

function getVerifierParamsLedger() {
    let params = {}

    params['init_params'] = [[24760, 21744], [], []];

    params['columns_rotations'] = [[], []]

    // For proof 1
    let base_params = loadParamsFromFile(path.join(__dirname, "/params/verifier_params_state_base.json"));
    params['init_params'][1] = base_params.init_params;
    params['columns_rotations'][0] = base_params.columns_rotations;

    // For proof 2
    let scalar_params = loadParamsFromFile(path.join(__dirname, "/params/verifier_params_state_scalar.json"));
    params['init_params'][2] = scalar_params.init_params;
    params['columns_rotations'][1] = scalar_params.columns_rotations;

    return params;
}

function getVerifierParamsAccount() {
    let params_file = path.join(__dirname, '/params/verifier_params_account.json');
    let account_path_params = loadParamsFromFile(params_file)
    return account_path_params;
}

task("validate_ledger_state", "Validate entire mina ledger state")
    .addParam("proof")
    .addParam("ledger")
    .setAction(async ({proof, ledger: ledger}, hre) => {
        // @ts-ignore
        const ethers = hre.ethers;
        // @ts-ignore
        const {deployer} = await hre.getNamedAccounts();
        console.log(ledger)
        let params = getVerifierParamsLedger();
        let inputProof = getFileContents(proof);
        let minaStateProof = await ethers.getContract("MinaState");
        let minaPlaceholderVerifier = await ethers.getContractAt('IMinaPlaceholderVerifier', minaStateProof.address);
        const tx = await minaPlaceholderVerifier.updateLedgerProof(ledger, inputProof, params['init_params'], params['columns_rotations'], {gasLimit: 40_500_000});
        const receipt = await tx.wait();
        console.log(receipt);
    });

task("validate_account_state", "Validate Mina's account state")
    .addParam("proof")
    .addParam("ledger")
    .addParam("state")
    .setAction(async ({proof, ledger: ledger, state}, hre) => {
        // @ts-ignore
        const ethers = hre.ethers;
        // @ts-ignore
        const {deployer} = await hre.getNamedAccounts();
        let params = getVerifierParamsAccount();
        let inputProof = getFileContents(proof);
        inputProof = inputProof.substring(2);
        let accountState = JSON.parse(getFileContents(state));
        let hexlifiedExtension = ethers.utils.hexlify(Buffer.from(accountState.proof_extension, "utf8"));
        let extendedProof = hexlifiedExtension + inputProof;
        delete accountState.proof_extension;
        accountState.state = accountState.state.split(",");
        let minaStateProof = await ethers.getContract("MinaState");
        let minaPlaceholderVerifier = await ethers.getContractAt('IMinaPlaceholderVerifier', minaStateProof.address);
        let tx = await minaPlaceholderVerifier.verifyAccountState(accountState, ledger, extendedProof, params['init_params'], params['columns_rotations'], {gasLimit: 40_500_000});
        const receipt = await tx.wait()
        console.log(receipt)
    });


