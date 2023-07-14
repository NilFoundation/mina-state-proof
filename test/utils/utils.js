const fs = require("fs");
const path = require("path");
const losslessJSON = require("lossless-json")
const {BigNumber} = require("ethers");


function loadParamsFromFile(jsonFile) {
    const named_params = losslessJSON.parse(fs.readFileSync(jsonFile, 'utf8'));
    let params = {};
    params.init_params = [];
    params.init_params.push(BigInt(named_params.modulus.value));
    params.init_params.push(BigInt(named_params.r.value));
    params.init_params.push(BigInt(named_params.max_degree.value));
    params.init_params.push(BigInt(named_params.lambda.value));
    params.init_params.push(BigInt(named_params.rows_amount.value));
    params.init_params.push(BigInt(named_params.omega.value));
    params.init_params.push(BigInt(named_params.D_omegas.length));
    for (let i in named_params.D_omegas) {
        params.init_params.push(BigInt(named_params.D_omegas[i].value))
    }
    params.init_params.push(named_params.step_list.length);
    for (let i in named_params.step_list) {
        params.init_params.push(BigInt(named_params.step_list[i].value))
    }
    params.init_params.push(named_params.arithmetization_params.length);
    for (let i in named_params.arithmetization_params) {
        params.init_params.push(BigInt(named_params.arithmetization_params[i].value))
    }

    params.columns_rotations = [];
    for (let i in named_params.columns_rotations) {
        let r = []
        for (let j in named_params.columns_rotations[i]) {
            r.push(BigInt(named_params.columns_rotations[i][j].value));
        }
        params.columns_rotations.push(r);
    }
    return params;
}

function getStateVerifierParams(baseParamsFile, scalarParamsFile) {
    let params = {}
    params['init_params'] = [[26048, 22920], [], []];
    params['columns_rotations'] = [[], []]
    
    // For proof 1
    let base_params = loadParamsFromFile(baseParamsFile);
    params['init_params'][1] = base_params.init_params;
    params['columns_rotations'][0] = base_params.columns_rotations;

    // For proof 2
    let scalar_params = loadParamsFromFile(scalarParamsFile);
    params['init_params'][2] = scalar_params.init_params;
    params['columns_rotations'][1] = scalar_params.columns_rotations;
    return params;
}

function getAccountVerifierParams(verifierParamsFile) {
    let account_path_params = loadParamsFromFile(verifierParamsFile);
    return account_path_params;
}

function getFileContents(filePath) {
    return fs.readFileSync(filePath, 'utf8');
}

module.exports = { getStateVerifierParams , getAccountVerifierParams,getFileContents};