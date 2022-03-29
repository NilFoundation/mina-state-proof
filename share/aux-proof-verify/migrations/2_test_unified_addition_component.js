const BN = require('bn.js');
const TestComponent = artifacts.require("TestUnifiedAdditionComponent");

module.exports = async function (deployer) {
  await deployer.deploy(
    TestComponent,
    new BN('40000000000000000000000000000000224698fc094cf91b992d30ed00000001', 16),
    new BN('26509649739312616830633500045428164374595609435618518653440390409995716485591', 10)
  );
};