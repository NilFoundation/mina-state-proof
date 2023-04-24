const hre = require('hardhat')
const { getNamedAccounts } = hre

module.exports = async function() {
    const {deployments, getNamedAccounts} = hre;
    const {deploy} = deployments;
    const {deployer, tokenOwner} = await getNamedAccounts();

    let libs = [
        "mina_scalar_gate0",
        "mina_scalar_gate1",
        "mina_scalar_gate2",
        "mina_scalar_gate3",
        "mina_scalar_gate4",
        "mina_scalar_gate8",
        "mina_scalar_gate9",
        "mina_scalar_gate10",
        "mina_scalar_gate11",
        "mina_scalar_gate12",
        "mina_scalar_gate13",
        "mina_scalar_gate14",
        "mina_scalar_gate15",
        "mina_scalar_gate16",
        "mina_scalar_gate17",
        "mina_scalar_gate18",
        "mina_scalar_gate19",
        "mina_scalar_gate20",
        "mina_scalar_gate21",
        "mina_scalar_gate22",
        "mina_base_gate0",
        "mina_base_gate1",
        "mina_base_gate2",
        "mina_base_gate3",
        "mina_base_gate4",
        "mina_base_gate5",
        "mina_base_gate6",
        "mina_base_gate7",
        "mina_base_gate8",
        "mina_base_gate9",
        "mina_base_gate10",
        "mina_base_gate11",
        "mina_base_gate12",
        "mina_base_gate13",
        "mina_base_gate14",
        "mina_base_gate15",
        "mina_base_gate16",
        "mina_base_gate16_1",
        "mina_base_gate17",
        "mina_base_gate18",
        "placeholder_verifier",
        "gate0",
        "gate1",
        "gate2",
        "gate3",
        "gate4",
        "gate5",
        "gate6",
        "gate7",
        "gate8",
        "gate9",
        "gate10",
    ]

    let deployedLib = {}
    for (let lib of libs){
        await deploy(lib, {
            from: deployer,
            log: true,
        });
        deployedLib[lib] = (await hre.deployments.get(lib)).address
    }

    await deploy('MinaPlaceholderVerifier', {
        from: deployer,
        libraries : deployedLib,
        log : true,
    })
}




module.exports.tags = ['minaPlaceholderVerifierFixture']
