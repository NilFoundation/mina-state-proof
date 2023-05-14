const {
    time,
    loadFixture,
} = require("@nomicfoundation/hardhat-network-helpers");
const {anyValue} = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
const {expect} = require("chai");
const hre = require('hardhat')
const fs = require("fs");
const path = require("path");
const losslessJSON = require("lossless-json")
const {BigNumber} = require("ethers");
const {getNamedAccounts} = hre

/* global BigInt */

describe('Mina state proof validation tests', function () {
    const {deployments, getNamedAccounts} = hre;
    const {deploy} = deployments;

    function loadParamsFromFile(jsonFile) {
        const named_params = losslessJSON.parse(fs.readFileSync(jsonFile, 'utf8'));
        params = {};
        params.init_params = [];
        params.init_params.push(BigInt(named_params.modulus.value));
        params.init_params.push(BigInt(named_params.r.value));
        params.init_params.push(BigInt(named_params.max_degree.value));
        params.init_params.push(BigInt(named_params.lambda.value));
        params.init_params.push(BigInt(named_params.rows_amount.value));
        params.init_params.push(BigInt(named_params.omega.value));
        params.init_params.push(BigInt(named_params.D_omegas.length));
        for (i in named_params.D_omegas) {
            params.init_params.push(BigInt(named_params.D_omegas[i].value))
        }
        params.init_params.push(named_params.step_list.length);
        for (i in named_params.step_list) {
            params.init_params.push(BigInt(named_params.step_list[i].value))
        }
        params.init_params.push(named_params.arithmetization_params.length);
        for (i in named_params.arithmetization_params) {
            params.init_params.push(BigInt(named_params.arithmetization_params[i].value))
        }

        params.columns_rotations = [];
        for (i in named_params.columns_rotations) {
            r = []
            for (j in named_params.columns_rotations[i]) {
                r.push(BigInt(named_params.columns_rotations[i][j].value));
            }
            params.columns_rotations.push(r);
        }
        return params;
    }


    function getVerifierParams() {
        let params = {}

        params['proof'] = fs.readFileSync(path.resolve(__dirname, "./data/proof_eval10.bin"), 'utf8');

        params['init_params'] = [[26048, 22920], [], []];

        params['columns_rotations'] = [[], []]

        // For proof 1
        let base_params = loadParamsFromFile(path.resolve(__dirname, "./data/base_eval10_params.json"));
        params['init_params'][1] = base_params.init_params;
        params['columns_rotations'][0] = base_params.columns_rotations;

        // For proof 2
        let scalar_params = loadParamsFromFile(path.resolve(__dirname, "./data/scalar_eval10_params.json"));
        params['init_params'][2] = scalar_params.init_params;
        params['columns_rotations'][1] = scalar_params.columns_rotations;

        return params;
    }

    function getVerifierParamsAccount() {
        let params = {}
    
        params['init_params'] = [[85340, 85340], [], []];
        params['columns_rotations'] = [[], []]
    
        // For proof 1
        params['init_params'][1].push(28948022309329048855892746252171976963363056481941560715954676764349967630337n)
        params['init_params'][1].push(9)
        params['init_params'][1].push(1023)
        params['init_params'][1].push(1)
        params['init_params'][1].push(1024)
        params['init_params'][1].push(21138537593338818067112636105753818200833244613779330379839660864802343411573n)
        params['init_params'][1].push(67)
        let D_omegas = [
            21138537593338818067112636105753818200833244613779330379839660864802343411573n,
            22954361264956099995527581168615143754787441159030650146191365293282410739685n,
            23692685744005816481424929253249866475360293751445976741406164118468705843520n,
            7356716530956153652314774863381845254278968224778478050456563329565810467774n,
            17166126583027276163107155648953851600645935739886150467584901586847365754678n,
            3612152772817685532768635636100598085437510685224817206515049967552954106764n,
            14450201850503471296781915119640920297985789873634237091629829669980153907901n,
            199455130043951077247265858823823987229570523056509026484192158816218200659n,
            24760239192664116622385963963284001971067308018068707868888628426778644166363n,
        ]
        params['init_params'][1].push(D_omegas.length)
        params['init_params'][1].push(...D_omegas)
        let q = [0, 0, 1]
        params['init_params'][1].push(q.length)
        params['init_params'][1].push(...q)
    
        params['columns_rotations'][0] = []
        params['columns_rotations'][0] = [
            [0,1],
            [0,1],
            [0,1],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0],
            [0]]
    
        let step_list = [1,1,1,1,1,1,1,1,1]
        params['init_params'][1].push(step_list.length)
        params['init_params'][1].push(...step_list)
    
        let arithmetization_params = [15, 5, 5, 20]
        params['init_params'][1].push(arithmetization_params.length)
        params['init_params'][1].push(...arithmetization_params)
    
        return params;
    }

    describe('Ledger Proof - Success', function () {
        it("Should validate correct proof ", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let mina_base_gate_argument_contract = await ethers.getContract('mina_base_split_gen');
            let mina_scalar_gate_argument_contract = await ethers.getContract('mina_scalar_split_gen');
            let placeholder_verifier_contract = await ethers.getContract('PlaceholderVerifier');

            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await expect(minaPlaceholderVerifierIF.verifyLedgerState("helloWorld",
                params['proof'], params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "LedgerProofValidationAccepted");
        });

        it("Should update and store proof ", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let mina_base_gate_argument_contract = await ethers.getContract('mina_base_split_gen');
            let mina_scalar_gate_argument_contract = await ethers.getContract('mina_scalar_split_gen');
            let placeholder_verifier_contract = await ethers.getContract('PlaceholderVerifier');

            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await minaPlaceholderVerifierIF.updateLedgerProof(
                "helloWorld",
                params['proof'], params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000})
        });

        it("Should validate previously updated & stored correct proof ", async function () {
            let params = getVerifierParams();
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            expect(await minaPlaceholderVerifierIF.isValidatedLedgerHash("helloWorld", {gasLimit: 30_500_000})).to.equal(true);
        });
    })

    describe.skip('Account Proof - Success', function () {
        it("Should validate correct proof ", async function () {
            let params = getVerifierParamsAccount();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let mina_base_gate_argument_contract = await ethers.getContract('mina_base_split_gen');
            let mina_scalar_gate_argument_contract = await ethers.getContract('mina_scalar_split_gen');
            let placeholder_verifier_contract = await ethers.getContract('PlaceholderVerifier');

            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await minaPlaceholderVerifierIF.updateLedgerProof("helloWorld",
                params['proof'], params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000}
            )

            const accountData = {
                public_key: "B62qre3ersHfzQckNuibViWTGyyKwZseztqrjPjBv6SQF384Rg6ESAy",
                balance: {
                    liquid: 5000n,
                    locked: 0n
                },
                state: [
                    "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x0000000000000000000000000000000000000000000000000000000000000002",
                    "0x0000000000000000000000000000000000000000000000000000000000000003",
                    "0x0000000000000000000000000000000000000000000000000000000000000004",
                    "0x0000000000000000000000000000000000000000000000000000000000000005",
                    "0x0000000000000000000000000000000000000000000000000000000000000006",
                    "0x0000000000000000000000000000000000000000000000000000000000000007",
                    "0x0000000000000000000000000000000000000000000000000000000000000008"
                ],
            };
            const dummyAccountProof = "0x112233445566778899";
            await minaPlaceholderVerifierIF.verifyAccountState(accountData, "helloWorld", dummyAccountProof,
                params['init_params'], params['columns_rotations']
            );
        });
    })

    describe("Ledger Proof - Failures", function () {
        it("Should emit event on incorrect proof validation", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture'])
            let mina_base_gate_argument_contract = await ethers.getContract('mina_base_split_gen');
            let mina_scalar_gate_argument_contract = await ethers.getContract('mina_scalar_split_gen');
            let placeholder_verifier_contract = await ethers.getContract('PlaceholderVerifier');

            params['proof'] = '0x4554480000000000000000000000000000000000000000000000000000000000'
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await expect(minaPlaceholderVerifierIF.verifyLedgerState(
                "helloWorld",
                params['proof'], params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "LedgerProofValidationFailed");
        });

        it("Should fail to update and store incorrect proof ", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let mina_base_gate_argument_contract = await ethers.getContract('mina_base_split_gen');
            let mina_scalar_gate_argument_contract = await ethers.getContract('mina_scalar_split_gen');
            let placeholder_verifier_contract = await ethers.getContract('PlaceholderVerifier');

            params['proof'] = '0x4554480000000000000000000000000000000000000000000000000000000000'
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            expect(await minaPlaceholderVerifierIF.updateLedgerProof(
                "helloWorld", params['proof'], params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "LedgerProofValidationFailed");
        });

        it("Should fail for incorrect hash", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture'])
            let mina_base_gate_argument_contract = await ethers.getContract('mina_base_split_gen');
            let mina_scalar_gate_argument_contract = await ethers.getContract('mina_scalar_split_gen');
            let placeholder_verifier_contract = await ethers.getContract('PlaceholderVerifier');

            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            expect(await minaPlaceholderVerifierIF.verifyLedgerState(
                "helloWorld", params['proof'], params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000})
            ).to.emit(minaPlaceholderVerifierIF, "InvalidLedgerHash");
        });
    })

    describe.skip('Account Proof - Failures', function () {
        it("Should fail if incorrect ledger hash provided along with proof ", async function () {
            let params = getVerifierParamsAccount();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            const accountData = {
                public_key: "B62qre3ersHfzQckNuibViWTGyyKwZseztqrjPjBv6SQF384Rg6ESAy",
                balance: {
                    liquid: 5000n,
                    locked: 0n
                },
                state: [
                    "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x0000000000000000000000000000000000000000000000000000000000000002",
                    "0x0000000000000000000000000000000000000000000000000000000000000003",
                    "0x0000000000000000000000000000000000000000000000000000000000000004",
                    "0x0000000000000000000000000000000000000000000000000000000000000005",
                    "0x0000000000000000000000000000000000000000000000000000000000000006",
                    "0x0000000000000000000000000000000000000000000000000000000000000007",
                    "0x0000000000000000000000000000000000000000000000000000000000000008"
                ],
            };
            const dummyAccountProof = "0x112233445566778899";
            await expect(await minaPlaceholderVerifierIF.verifyAccountState(accountData, "helloWorld", dummyAccountProof, params['init_params'], params['columns_rotations']))
                .to.emit(minaPlaceholderVerifierIF, "InvalidLedgerHash");
            ;
        });
    })
})
