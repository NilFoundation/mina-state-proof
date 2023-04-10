import {task} from "hardhat/config";
import fs from "fs";
import path from "path";
import {BigNumber} from "ethers";

function getFileContents(filePath) {
    return fs.readFileSync(filePath, 'utf8');
}

function getVerifierParams() {
    let params = {}

    params['init_params'] = [[200920, 416992], [], []];
    params['columns_rotations'] = [[], []]

    // For proof 1
    params['init_params'][1].push(28948022309329048855892746252171976963363056481941560715954676764349967630337n)
    params['init_params'][1].push(16)
    params['init_params'][1].push(131071)
    params['init_params'][1].push(1)
    params['init_params'][1].push(131072)
    params['init_params'][1].push(21090803083255360924969619711782040241928172562822879037017685322859036642027n)
    params['init_params'][1].push(67)
    let D_omegas = [
        21090803083255360924969619711782040241928172562822879037017685322859036642027n,
        10988054172925167713694812535142550583545019937971378974362050426778203868934n,
        22762810496981275083229264712375994604562198468579727082239970810950736657129n,
        26495698845590383240609604404074423972849566255661802313591097233811292788392n,
        13175653644678658737556805326666943932741525539026001701374450696535194715445n,
        18589158034707770508497743761528839450567399299956641192723316341154428793508n,
        5207999989657576140891498154897385491612440083899963290755562031717636435093n,
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
    params['columns_rotations'][0] = [[0, 1, -1,],
        [0, 1, -1,],
        [0, 1, -1,],
        [0, 1, -1,],
        [0, 1, -1,],
        [0, 1, -1,],
        [0, 1,],
        [0, 1, -1,],
        [0, 1, -1,],
        [0, 1, -1,],
        [0, 1, -1,],
        [0, 1, -1,],
        [0, -1,],
        [0, -1,],
        [0, -1,],
        [0,], [0,], [0,], [0,], [0,], [0,], [0,], [0,], [0,], [0,], [0,],
        [0,],
        [0,], [0,], [0,], [0,], [0,], [0,], [0,], [0,], [0,], [0,], [0,],
        [0,],
        [0,], [0,], [0,], [0,], [0,], [0,], [0,], [0,]]

    let step_list = Array(16).fill(1)
    params['init_params'][1].push(step_list.length)
    params['init_params'][1].push(...step_list)

    let arithmetization_params = [15, 1, 1, 30]
    params['init_params'][1].push(arithmetization_params.length)
    params['init_params'][1].push(...arithmetization_params)

    //For proof 2
    params['init_params'][2] = []
    params['init_params'][2].push(28948022309329048855892746252171976963363056481941647379679742748393362948097n)
    params['init_params'][2].push(17)
    params['init_params'][2].push(262143)
    params['init_params'][2].push(1)
    params['init_params'][2].push(262144)
    params['init_params'][2].push(8161969249340783987761324711568624975237533050088779660262354930448819472052n)
    params['init_params'][2].push(67)

    D_omegas = [
        8161969249340783987761324711568624975237533050088779660262354930448819472052n,
        3886175100316118007371640746558739196649017900618601982075775335403275343459n,
        3858771995582327432623779775365915133688365037773367998141837063280219681489n,
        27089958442152501875810132276080823478704708607790900112361486996955217465106n,
        4962941270686734179124851736304457391480500057160355425531240539629160391514n,
        24698565941386146905064983207718127075873794584889341429041780832303738174137n,
        19342635675472973030958703460855586838246018162847467754269942910820871215401n,
        5032528351894390093615884424140114457150112013647720477219996067428709871325n,
        22090338513913049959963172982829382927035332346328063108352787446596923585926n,
        25165177819627306674965102406249393023864159703467953217189030835046387946339n,
        20406162866908888653425069393176433404558180282626759233524330349859168426307n,
        24118114923975171970075748640221677083961848771131734379542430306560974812756n,
        25227411734906969830001887161842150884725543104432911324890985713481442730673n,
        2799975530188595297561234903824607897079093402088395318086163719444963742400n,
        19366951025174438143523342051730202536500593522667444600037456491292628123146n,
        4855188899445002300170730717563617051094175372704778513906105166874447905568n,
        4265513433803163958251475299683560813532603332905934989976535652412227143402n,
    ]

    params['init_params'][2].push(D_omegas.length)
    params['init_params'][2].push(...D_omegas)
    q = [0, 0, 1]
    params['init_params'][2].push(q.length)
    params['init_params'][2].push(...q)

    step_list = Array(17).fill(1)
    params['init_params'][2].push(step_list.length)
    params['init_params'][2].push(...step_list)

    arithmetization_params = [15, 1, 1, 30] // witness, public_input, constant, selector
    params['init_params'][2].push(arithmetization_params.length)
    params['init_params'][2].push(...arithmetization_params)

    for (let i = 0; i < 47; ++i) {
        params['columns_rotations'][1].push([0])
    }

    params['columns_rotations'][1][0] = [0, 1, -1]
    params['columns_rotations'][1][1] = [0, -1, 1]
    params['columns_rotations'][1][2] = [0, 1]
    params['columns_rotations'][1][5] = [0, -1]
    params['columns_rotations'][1][13] = [0, 1]

    return params;
}

task("validate_ledger_state", "Validate entire mina ledger state")
    .addParam("proof")
    .addParam("ledger")
    .setAction(async ({proof, ledger: ledger}, hre) => {
        // @ts-ignore
        const ethers = hre.ethers;
        // @ts-ignore
        const {deployer} = await hre.getNamedAccounts();
        console.log(ledger)
        let params = getVerifierParams();
        let inputProof = getFileContents(proof);
        let minaPlaceholderVerifier = await ethers.getContract('MinaPlaceholderVerifier');
        let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
        const tx = await minaPlaceholderVerifierIF.updateLedgerProof(ledger, inputProof, params['init_params'], params['columns_rotations'], {gasLimit: 40_500_000})
        const receipt = await tx.wait()
        console.log(receipt)
    });

task("validate_account_state", "Validate entire mina ledger state")
    .addParam("proof")
    .addParam("ledger")
    .addParam("state")
    .setAction(async ({proof, ledger: ledger, state}, hre) => {
        // @ts-ignore
        const ethers = hre.ethers;
        // @ts-ignore
        const {deployer} = await hre.getNamedAccounts();
        let params = getVerifierParams();
        let accountState = JSON.parse(getFileContents(state));
        accountState.state = accountState.state.split(",");
        const dummyAccountProof = "0x112233445566778899";
        let minaPlaceholderVerifier = await ethers.getContract('MinaPlaceholderVerifier');
        let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
        let tx = await minaPlaceholderVerifierIF.verifyAccountState(accountState, ledger, dummyAccountProof, params['init_params'], params['columns_rotations'], {gasLimit: 40_500_000});
        const receipt = await tx.wait()
        console.log(receipt)
    });


