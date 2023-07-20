import {task} from "hardhat/config";
import fs from "fs";
import path from "path";
import losslessJSON from "lossless-json";
import {getFileContents, getStateVerifierParams,getAccountVerifierParams} from "../test/utils/utils";

const baseParamsFile = path.join(__dirname, "../circuits/params/verifier_params_state_base.json");
const scalarParamsFile =path.join(__dirname, "../circuits//params/verifier_params_state_scalar.json");
const accountParamsFile = path.join(__dirname, '../circuits//params/verifier_params_account.json');


task("validate_ledger_state", "Validate entire mina ledger state")
    .addParam("proof")
    .addParam("ledger")
    .setAction(async ({proof, ledger: ledger}, hre) => {
        // @ts-ignore
        const ethers = hre.ethers;
        // @ts-ignore
        const {deployer} = await hre.getNamedAccounts();
        console.log(ledger)
        let params = getStateVerifierParams(baseParamsFile,scalarParamsFile);
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
        let params = getAccountVerifierParams(accountParamsFile);
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


