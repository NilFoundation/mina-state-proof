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

    await deploy('MinaStateProof',{
        from:deployer,
        args:[
            verifier_address,
            mina_base_split_gen_address,
            mina_scalar_split_gen_address

        ],
        log:true
    })

    state_proof_address = (await hre.deployments.get('MinaStateProof')).address;
    await deploy('MinaState',{
        from:deployer,
        args:[
            state_proof_address
        ],
        log:true
    })
/*    const MinaStateProofFactory = await hre.ethers.getContractFactory("MinaStateProof");
    const MinaStateProof = await MinaStateProofFactory.deploy(
        (await hre.deployments.get('PlaceholderVerifier')).address,
        (await hre.deployments.get('mina_base_split_gen')).address,
        (await hre.deployments.get('mina_scalar_split_gen')).address);
    await MinaStateProof.deployed();

    console.log(`MinaStateProof is deployed to ${MinaStateProof.address}`);

    const MinaStateFactory = await hre.ethers.getContractFactory("MinaState");
    const MinaState = await MinaStateFactory.deploy(MinaStateProof.address);
    await MinaState.deployed();

    console.log(`MinaState is deployed to ${MinaState.address}`);*/
}

module.exports.tags = ['minaPlaceholderVerifierFixture']