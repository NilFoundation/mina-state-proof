linked_mina_state_libs_names = [
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
]

def init_placeholder_params(proof_path):
    params = dict()
    f = open(proof_path)
    params["proof"] = f.read()
    f.close()

    params['init_params'] = [[200920, 416992], [], []]  # params[0][0] -- first proof length, params[0][1] -- full length
    params['columns_rotations'] = [[], []]

    # For proof 1
    params['init_params'][1].append(28948022309329048855892746252171976963363056481941560715954676764349967630337)
    params['init_params'][1].append(16)
    params['init_params'][1].append(131071)
    params['init_params'][1].append(1)
    params['init_params'][1].append(131072)
    params['init_params'][1].append(21090803083255360924969619711782040241928172562822879037017685322859036642027)
    params['init_params'][1].append(67)
    D_omegas = [21090803083255360924969619711782040241928172562822879037017685322859036642027, 10988054172925167713694812535142550583545019937971378974362050426778203868934, 22762810496981275083229264712375994604562198468579727082239970810950736657129, 26495698845590383240609604404074423972849566255661802313591097233811292788392, 13175653644678658737556805326666943932741525539026001701374450696535194715445, 18589158034707770508497743761528839450567399299956641192723316341154428793508, 5207999989657576140891498154897385491612440083899963290755562031717636435093, 21138537593338818067112636105753818200833244613779330379839660864802343411573, 22954361264956099995527581168615143754787441159030650146191365293282410739685, 23692685744005816481424929253249866475360293751445976741406164118468705843520, 7356716530956153652314774863381845254278968224778478050456563329565810467774, 17166126583027276163107155648953851600645935739886150467584901586847365754678, 3612152772817685532768635636100598085437510685224817206515049967552954106764, 14450201850503471296781915119640920297985789873634237091629829669980153907901, 199455130043951077247265858823823987229570523056509026484192158816218200659, 24760239192664116622385963963284001971067308018068707868888628426778644166363,
                ]
    params['init_params'][1].append(len(D_omegas))
    params['init_params'][1].extend(D_omegas)
    q = [0, 0, 1]
    params['init_params'][1].append(len(q))
    params['init_params'][1].extend(q)

    params['columns_rotations'][0] = []
    params['columns_rotations'][0] = [[0, 1, -1, ],
                                      [0, 1, -1, ],
                                      [0, 1, -1, ],
                                      [0, 1, -1, ],
                                      [0, 1, -1, ],
                                      [0, 1, -1, ],
                                      [0, 1, ],
                                      [0, 1, -1, ],
                                      [0, 1, -1, ],
                                      [0, 1, -1, ],
                                      [0, 1, -1, ],
                                      [0, 1, -1, ],
                                      [0, -1, ],
                                      [0, -1, ],
                                      [0, -1, ],
                                      [0, ], [0, ], [0, ], [0, ], [0, ], [0, ], [0, ], [0, ], [0, ], [0, ], [0, ],
                                      [0, ],
                                      [0, ], [0, ], [0, ], [0, ], [0, ], [0, ], [0, ], [0, ], [0, ], [0, ], [0, ],
                                      [0, ],
                                      [0, ], [0, ], [0, ], [0, ], [0, ], [0, ], [0, ], [0, ]]
    step_list = [1] * 16
    params['init_params'][1].append(len(step_list))
    params['init_params'][1].extend(step_list)  # step_list
    arithmetization_params = [15, 1, 1, 30] # witness, public_input, constant, selector
    params['init_params'][1].append((len(arithmetization_params)))
    params['init_params'][1].extend(arithmetization_params)

    # For proof 2
    params['init_params'][2] = []
    params['init_params'][2].append(28948022309329048855892746252171976963363056481941647379679742748393362948097)
    params['init_params'][2].append(17)
    params['init_params'][2].append(262143)
    params['init_params'][2].append(1)
    params['init_params'][2].append(262144)
    params['init_params'][2].append(8161969249340783987761324711568624975237533050088779660262354930448819472052)
    params['init_params'][2].append(67)
    D_omegas = [8161969249340783987761324711568624975237533050088779660262354930448819472052, 3886175100316118007371640746558739196649017900618601982075775335403275343459, 3858771995582327432623779775365915133688365037773367998141837063280219681489, 27089958442152501875810132276080823478704708607790900112361486996955217465106, 4962941270686734179124851736304457391480500057160355425531240539629160391514, 24698565941386146905064983207718127075873794584889341429041780832303738174137, 19342635675472973030958703460855586838246018162847467754269942910820871215401, 5032528351894390093615884424140114457150112013647720477219996067428709871325, 22090338513913049959963172982829382927035332346328063108352787446596923585926, 25165177819627306674965102406249393023864159703467953217189030835046387946339, 20406162866908888653425069393176433404558180282626759233524330349859168426307, 24118114923975171970075748640221677083961848771131734379542430306560974812756, 25227411734906969830001887161842150884725543104432911324890985713481442730673, 2799975530188595297561234903824607897079093402088395318086163719444963742400, 19366951025174438143523342051730202536500593522667444600037456491292628123146, 4855188899445002300170730717563617051094175372704778513906105166874447905568, 4265513433803163958251475299683560813532603332905934989976535652412227143402,
                ]

    params['init_params'][2].append(len(D_omegas))
    params['init_params'][2].extend(D_omegas)
    q = [0, 0, 1]
    params['init_params'][2].append(len(q))
    params['init_params'][2].extend(q)

    step_list = [1] * 17
    params['init_params'][2].append(len(step_list))
    params['init_params'][2].extend(step_list)  # step_list

    arithmetization_params = [15, 1, 1, 30] # witness, public_input, constant, selector
    params['init_params'][2].append((len(arithmetization_params)))
    params['init_params'][2].extend(arithmetization_params)


    for i in range(47):
        params['columns_rotations'][1].append([0, ])
    params['columns_rotations'][1][0] = [0, 1, -1]
    params['columns_rotations'][1][1] = [0, -1, 1]
    params['columns_rotations'][1][2] = [0, 1]
    params['columns_rotations'][1][5] = [0, -1]
    params['columns_rotations'][1][13] = [0, 1]

    params['log_file'] = 'logs/mina_state_proof.json'
    return params