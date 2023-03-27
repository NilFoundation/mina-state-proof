import { Add } from './Add';
import {
  isReady,
  shutdown,
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate,
} from 'snarkyjs';

/*
 * This file specifies how to test the `Add` example smart contract. It is safe to delete this file and replace
 * with your own tests.
 *
 * See https://docs.minaprotocol.com/zkapps for more info.
 */

let proofsEnabled = false;

describe('Add', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: Add;

  beforeAll(async () => {
    await isReady;
    if (proofsEnabled) Add.compile();
  });

  beforeEach(() => {
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);
    ({ privateKey: deployerKey, publicKey: deployerAccount } =
      Local.testAccounts[0]);
    ({ privateKey: senderKey, publicKey: senderAccount } =
      Local.testAccounts[1]);
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new Add(zkAppAddress);
  });

  afterAll(() => {
    // `shutdown()` internally calls `process.exit()` which will exit the running Jest process early.
    // Specifying a timeout of 0 is a workaround to defer `shutdown()` until Jest is done running all tests.
    // This should be fixed with https://github.com/MinaProtocol/mina/issues/10943
    setTimeout(shutdown, 0);
  });

  async function localDeploy() {
    const txn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkApp.deploy();
    });
    await txn.prove();
    // this tx needs .sign(), because `deploy()` adds an account update that requires signature authorization
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }

  it('generates and deploys the `Add` smart contract', async () => {
    await localDeploy();
    const num1 = zkApp.num1.get();
    const num2 = zkApp.num2.get();
    const num3 = zkApp.num3.get();
    const num4 = zkApp.num4.get();
    const num5 = zkApp.num5.get();
    const num6 = zkApp.num6.get();
    const num7 = zkApp.num7.get();
    const num8 = zkApp.num8.get();

    expect(num1).toEqual(Field(1));
    expect(num2).toEqual(Field(2));
    expect(num3).toEqual(Field(3));
    expect(num4).toEqual(Field(4));
    expect(num5).toEqual(Field(5));
    expect(num6).toEqual(Field(6));
    expect(num7).toEqual(Field(7));
    expect(num8).toEqual(Field(8));
  });

  it('correctly updates the num state on the `Add` smart contract', async () => {
    await localDeploy();

    // update transaction
    const txn = await Mina.transaction(senderAccount, () => {
      zkApp.update();
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    const updatedNum1 = zkApp.num1.get();
    const updatedNum2 = zkApp.num2.get();
    const updatedNum3 = zkApp.num3.get();
    const updatedNum4 = zkApp.num4.get();
    const updatedNum5 = zkApp.num5.get();
    const updatedNum6 = zkApp.num6.get();
    const updatedNum7 = zkApp.num7.get();
    const updatedNum8 = zkApp.num8.get();

    expect(updatedNum1).toEqual(Field(2));
    expect(updatedNum2).toEqual(Field(4));
    expect(updatedNum3).toEqual(Field(6));
    expect(updatedNum4).toEqual(Field(8));
    expect(updatedNum5).toEqual(Field(10));
    expect(updatedNum6).toEqual(Field(12));
    expect(updatedNum7).toEqual(Field(14));
    expect(updatedNum8).toEqual(Field(16));

  });
});
