const TestMerkleProofVerifier = artifacts.require("TestMerkleProofVerifier");
const TestFriVerifier = artifacts.require("TestFriVerifier");
const TestLpcVerifier = artifacts.require("TestLpcVerifier");
const TestPermutationArgument = artifacts.require("TestPermutationArgument");
const TestPermutationArgumentCalldataInput = artifacts.require("TestPermutationArgumentCalldataInput");
const TestUnifiedAdditionComponent = artifacts.require("TestUnifiedAdditionComponent");
const TestUnifiedAdditionComponentCalldataInput = artifacts.require("TestUnifiedAdditionComponentCalldataInput");
const TestPoseidonComponent = artifacts.require("TestPoseidonComponent");

const PoseidonComponentSplitLib0 = artifacts.require("poseidon_gate0");
const PoseidonComponentSplitLib1 = artifacts.require("poseidon_gate1");
const PoseidonComponentSplitLib2 = artifacts.require("poseidon_gate2");
const PoseidonComponentSplitLib3 = artifacts.require("poseidon_gate3");
const PoseidonComponentSplitLib4 = artifacts.require("poseidon_gate4");
const PoseidonComponentSplitLib5 = artifacts.require("poseidon_gate5");
const PoseidonComponentSplitLib6 = artifacts.require("poseidon_gate6");
const PoseidonComponentSplitLib7 = artifacts.require("poseidon_gate7");
const PoseidonComponentSplitLib8 = artifacts.require("poseidon_gate8");
const PoseidonComponentSplitLib9 = artifacts.require("poseidon_gate9");
const PoseidonComponentSplitLib10 = artifacts.require("poseidon_gate10");
const TestPoseidonComponentSplitGen = artifacts.require("TestPoseidonComponentSplitGen");

const TestRedshiftVerifierUnifiedAddition = artifacts.require("TestRedshiftVerifierUnifiedAddition");
const TestRedshiftVerifierUnifiedAdditionCalldataInput = artifacts.require("TestRedshiftVerifierUnifiedAdditionCalldataInput");
const TestRedshiftVerifierPoseidon = artifacts.require("TestRedshiftVerifierPoseidon");
const TestRedshiftVerifierPoseidonGen = artifacts.require("TestRedshiftVerifierPoseidonGen");

module.exports = function (deployer) {
  deployer.deploy(TestMerkleProofVerifier);
  deployer.deploy(TestFriVerifier);
  deployer.deploy(TestLpcVerifier);
  deployer.deploy(TestPermutationArgument);
  deployer.deploy(TestPermutationArgumentCalldataInput);
  deployer.deploy(TestUnifiedAdditionComponent);
  deployer.deploy(TestUnifiedAdditionComponentCalldataInput);
  deployer.deploy(TestPoseidonComponent);

  deployer.deploy(PoseidonComponentSplitLib0);
  deployer.deploy(PoseidonComponentSplitLib1);
  deployer.deploy(PoseidonComponentSplitLib2);
  deployer.deploy(PoseidonComponentSplitLib3);
  deployer.deploy(PoseidonComponentSplitLib4);
  deployer.deploy(PoseidonComponentSplitLib5);
  deployer.deploy(PoseidonComponentSplitLib6);
  deployer.deploy(PoseidonComponentSplitLib7);
  deployer.deploy(PoseidonComponentSplitLib8);
  deployer.deploy(PoseidonComponentSplitLib9);
  deployer.deploy(PoseidonComponentSplitLib10);
  deployer.link(PoseidonComponentSplitLib0, TestPoseidonComponentSplitGen);
  deployer.link(PoseidonComponentSplitLib1, TestPoseidonComponentSplitGen);
  deployer.link(PoseidonComponentSplitLib2, TestPoseidonComponentSplitGen);
  deployer.link(PoseidonComponentSplitLib3, TestPoseidonComponentSplitGen);
  deployer.link(PoseidonComponentSplitLib4, TestPoseidonComponentSplitGen);
  deployer.link(PoseidonComponentSplitLib5, TestPoseidonComponentSplitGen);
  deployer.link(PoseidonComponentSplitLib6, TestPoseidonComponentSplitGen);
  deployer.link(PoseidonComponentSplitLib7, TestPoseidonComponentSplitGen);
  deployer.link(PoseidonComponentSplitLib8, TestPoseidonComponentSplitGen);
  deployer.link(PoseidonComponentSplitLib9, TestPoseidonComponentSplitGen);
  deployer.link(PoseidonComponentSplitLib10, TestPoseidonComponentSplitGen);
  deployer.deploy(TestPoseidonComponentSplitGen);

  deployer.deploy(TestRedshiftVerifierUnifiedAddition);
  deployer.deploy(TestRedshiftVerifierUnifiedAdditionCalldataInput);
  deployer.deploy(TestRedshiftVerifierPoseidon);

  deployer.link(PoseidonComponentSplitLib0, TestRedshiftVerifierPoseidonGen);
  deployer.link(PoseidonComponentSplitLib1, TestRedshiftVerifierPoseidonGen);
  deployer.link(PoseidonComponentSplitLib2, TestRedshiftVerifierPoseidonGen);
  deployer.link(PoseidonComponentSplitLib3, TestRedshiftVerifierPoseidonGen);
  deployer.link(PoseidonComponentSplitLib4, TestRedshiftVerifierPoseidonGen);
  deployer.link(PoseidonComponentSplitLib5, TestRedshiftVerifierPoseidonGen);
  deployer.link(PoseidonComponentSplitLib6, TestRedshiftVerifierPoseidonGen);
  deployer.link(PoseidonComponentSplitLib7, TestRedshiftVerifierPoseidonGen);
  deployer.link(PoseidonComponentSplitLib8, TestRedshiftVerifierPoseidonGen);
  deployer.link(PoseidonComponentSplitLib9, TestRedshiftVerifierPoseidonGen);
  deployer.link(PoseidonComponentSplitLib10, TestRedshiftVerifierPoseidonGen);
  deployer.deploy(TestRedshiftVerifierPoseidonGen);
};
