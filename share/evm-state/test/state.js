const state = artifacts.require("state");

/*
 * uncomment accounts to access the test accounts made available by the
 * Ethereum client
 * See docs: https://www.trufflesuite.com/docs/truffle/testing/writing-tests-in-javascript
 */
contract("state", function (/* accounts */) {
  it("should assert true", async function () {
    await state.deployed();
    return assert.isTrue(true);
  });
});
