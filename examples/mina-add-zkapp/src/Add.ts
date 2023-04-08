import { Field, SmartContract, state, State, method } from 'snarkyjs';

/**
 * Basic Example
 * See https://docs.minaprotocol.com/zkapps for more info.
 *
 * The Add contract initializes the state variable 'num' to be a Field(1) value by default when deployed.
 * When the 'update' method is called, the Add contract adds Field(2) to its 'num' contract state.
 *
 * This file is safe to delete and replace with your own contract.
 */
export class Add extends SmartContract {
  @state(Field) num1 = State<Field>();
  @state(Field) num2 = State<Field>();
  @state(Field) num3 = State<Field>();
  @state(Field) num4 = State<Field>();
  @state(Field) num5 = State<Field>();
  @state(Field) num6 = State<Field>();
  @state(Field) num7 = State<Field>();
  @state(Field) num8 = State<Field>();
  init() {
    super.init();
    this.num1.set(Field(1));
    this.num2.set(Field(2));
    this.num3.set(Field(3));
    this.num4.set(Field(4));
    this.num5.set(Field(5));
    this.num6.set(Field(6));
    this.num7.set(Field(7));
    this.num8.set(Field(8));
  }

  @method update() {
    const currentState1 = this.num1.get();
    const currentState2 = this.num2.get();
    const currentState3 = this.num3.get();
    const currentState4 = this.num4.get();
    const currentState5 = this.num5.get();
    const currentState6 = this.num6.get();
    const currentState7 = this.num7.get();
    const currentState8 = this.num8.get();

    // precondition that links this.num[1-8].get() to the actual on-chain state
    this.num1.assertEquals(currentState1);
    this.num2.assertEquals(currentState2);
    this.num3.assertEquals(currentState3);
    this.num4.assertEquals(currentState4);
    this.num5.assertEquals(currentState5);
    this.num6.assertEquals(currentState6);
    this.num7.assertEquals(currentState7);
    this.num8.assertEquals(currentState8);


    this.num1.set(currentState1.add(1));
    this.num2.set(currentState2.add(2));
    this.num3.set(currentState3.add(3));
    this.num4.set(currentState4.add(4));
    this.num5.set(currentState5.add(5));
    this.num6.set(currentState6.add(6));
    this.num7.set(currentState7.add(7));
    this.num8.set(currentState8.add(8));

  }
}
