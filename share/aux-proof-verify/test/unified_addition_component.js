const BN = require('bn.js');
const TestComponent = artifacts.require("TestUnifiedAdditionComponent");

contract("Unified addition component evaluation", accounts => {
    it("Case 1", async () => {
        const instance = await TestComponent.deployed();
        await instance.evaluate('0x1559afad11ba7ff3d55d143785c5eff549008c348b35ca61eaa6128b655512770999932d1a7506a758436fa6c95b03720e13c68d6cb1f5ed17a053c32acab0ab14ac314c00480dc9608454a6282c7ee4ab89c3af407b32df3742ff63b89817b408fa5c6a0b0652595588d141e9d7b235702354f1fb9649bccc96450f4a26ab09056218a26b3f380732b4abe9595ab3de6c4916340a01106d813f7983146b9d180a34193f84dd6355576bf80d58d04089bc3cc45a5f4db7aab67ea1bdcf160e0d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002bd3e90a8970cb5fc2e8d7384e001dee3bf7322f23fdf16b5bbb10beab706e5c000000000000000000000000000000000000000000000000000000000000000026d81a6b96b76bfad6cd9f409731fa9ff9fbd6d2fad63d5dd3fbafe8202fdbbe190390acb2c6b8865f64bac96231a4c06a6a0f9e945d2aa7cdde9664a026b2cf');
        const evaluation_result = await instance.m_evaluation_result();
        assert.equal(
            evaluation_result.toString(10),
            '2187611903631573800010139566678334142237983618461939715906907249863037036657',
            'Gate evaluation result is not correct!'
        );
        const theta_acc_result = await instance.m_theta_acc();
        assert.equal(
            theta_acc_result.toString(10),
            '22776621096326636850168989734402224351450482466532466652833512923156695827432',
            'Theta accumulator result is not correct!'
        );
    });
});

