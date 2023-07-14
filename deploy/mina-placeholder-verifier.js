const hre = require('hardhat')
const {getNamedAccounts} = hre

module.exports = async function () {
    const {deployments, getNamedAccounts} = hre;
    const {deploy} = deployments;
    const {deployer, tokenOwner} = await getNamedAccounts();

    let libs = [
        "mina_base_gate0",
        "mina_base_gate4",
        "mina_base_gate7",
        "mina_base_gate10",
        "mina_base_gate13",
        "mina_base_gate15",
        "mina_base_gate16",
        "mina_base_gate16_1"
    ]

    let deployedLib = {}
    for (let lib of libs) {
        await deploy(lib, {
            from: deployer,
            log: true,
        });
        deployedLib[lib] = (await hre.deployments.get(lib)).address
    }

    await deploy('mina_base_split_gen', {
        from: deployer,
        libraries: deployedLib,
        log: true,
    });

    libs = [
        "mina_scalar_gate0",
        "mina_scalar_gate3",
        "mina_scalar_gate8",
        "mina_scalar_gate10",
        "mina_scalar_gate12",
        "mina_scalar_gate14",
        "mina_scalar_gate16",
        "mina_scalar_gate18",
        "mina_scalar_gate22",
    ]

    deployedLib = {}
    for (let lib of libs) {
        await deploy(lib, {
            from: deployer,
            log: true,
        });
        deployedLib[lib] = (await hre.deployments.get(lib)).address
    }

    await deploy('mina_scalar_split_gen', {
        from: deployer,
        libraries: deployedLib,
        log: true,
    });

    libs = [
        "account_gate0",
        "account_gate1",
        "account_gate2",
        "account_gate3",
        "account_gate4",
        "account_gate5",
        "account_gate6",
        "account_gate7",
        "account_gate8",
        "account_gate9",
        "account_gate10",
        "account_gate11",
        "account_gate12"
    ]
    deployedLib = {}
    for (let lib of libs) {
        await deploy(lib, {
            from: deployer,
            log: true,
        });
        deployedLib[lib] = (await hre.deployments.get(lib)).address
    }

    await deploy('account_proof_split_gen', {
        from: deployer,
        libraries: deployedLib,
        log: true,
    });

    libs = [
        "placeholder_verifier"
    ]
    deployedLib = {}
    for (let lib of libs) {
        await deploy(lib, {
            from: deployer,
            log: true,
        });
        deployedLib[lib] = (await hre.deployments.get(lib)).address
    }

    await deploy('PlaceholderVerifier', {
        from: deployer,
        libraries: deployedLib,
        log: true,
    });

    verifier_address = (await hre.deployments.get('PlaceholderVerifier')).address;
    mina_base_split_gen_address = (await hre.deployments.get('mina_base_split_gen')).address;
    mina_scalar_split_gen_address = (await hre.deployments.get('mina_scalar_split_gen')).address;
    account_split_gen_address = (await hre.deployments.get('account_proof_split_gen')).address;

    await deploy('MinaStateProof',{
        from:deployer,
        args:[
            verifier_address,
            mina_base_split_gen_address,
            mina_scalar_split_gen_address

        ],
        log:true
    })

    await deploy('AccountPathProof',{
        from:deployer,
        args:[
            verifier_address,
            account_split_gen_address,

        ],
        log:true
    })

    state_proof_address = (await hre.deployments.get('MinaStateProof')).address;
    account_proof_address = (await hre.deployments.get('AccountPathProof')).address;
    MinaState = await deploy('MinaState',{
        from:deployer,
        args:[
            state_proof_address,
            account_proof_address,
        ],
        log:true
    })
}

module.exports.tags = ['minaPlaceholderVerifierFixture']