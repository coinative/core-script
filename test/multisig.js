var Script = require('../');
var opcodes = Script.opcodes;

function hex(hex) { return new Buffer(hex, 'hex'); }

var fixtures = [
  {
    name: '8d2931d3160f41c81ba4d72ca34245bb22fc2c0f0ece6d6db0ab5e990e95cfde/2',
    keys: [
      '03c86e3c49a99dd688c6c6ad05d725b6a04ef19836b13d3e90ef282fc4f2f9ee71',
      '02c0189e96fbf6ff5953219b28399e22934e84d746f1ccbcb374186733e406245c'
    ],
    sigs: 1,
    script: '512103c86e3c49a99dd688c6c6ad05d725b6a04ef19836b13d3e90ef282fc4f2f9ee712102c0189e96fbf6ff5953219b28399e22934e84d746f1ccbcb374186733e406245c52ae'
  },
  {
    name: '2fdd5eb207711f8d0769c3f8dadf0a97bec0ea0a3b11940358e12703bccaeb8b/3',
    keys: [
      '03b4305181c29d13c3e8d0d0b4b85037df96b00656aa780e604c69ca7bf604019b',
      '024ca6ea3a28a58a0711ddb35eefb3f01e06b8be528b2b6e6834d98999d2f2fc6a'
    ],
    sigs: 1,
    script: '512103b4305181c29d13c3e8d0d0b4b85037df96b00656aa780e604c69ca7bf604019b21024ca6ea3a28a58a0711ddb35eefb3f01e06b8be528b2b6e6834d98999d2f2fc6a52ae'
  },
  {
    name: '8708d411b92bb5741c2219452931a849c2e312906ec51f18e8499dcf9e1377eb/2',
    keys: [
      '028fada18ecd12fdee727c4bfbdbc53b91615b456eeb09201b068fbf495331366a',
      '0272f1bc38bf27f96379d2d5387a51ac8aa4cf8aa8980122412b6e1ac086dfd317',
      '0261233085ff36e92142cf0a4c4b9a2dfb2d22f9045c06dcb1fc4d2d6870c918ec'
    ],
    sigs: 1,
    script: '5121028fada18ecd12fdee727c4bfbdbc53b91615b456eeb09201b068fbf495331366a210272f1bc38bf27f96379d2d5387a51ac8aa4cf8aa8980122412b6e1ac086dfd317210261233085ff36e92142cf0a4c4b9a2dfb2d22f9045c06dcb1fc4d2d6870c918ec53ae'
  },
  {
    name: '4bfd9cef10c95c628779f8d80d676f08428c118ce4587a7c9ddc5266fcb88dc6/2 (uncompressed)',
    keys: [
      '041ce544058996033a34adb07be380e63956c588dd036d20824447d88700ec91f45a98894bbbdab68ac304b5e68f77ea2f614516d0ace35f76e3b376b9917d6c84',
      '04db5efff14362653c0fc2e5437ac964dd3e093110c8fbcd5d9fd135ec3c98dc926d26b344def4397c3d99ebbd56e35c53cdd501e2c7a9a0cc5c2b04e7d0a38751',
      '043b9264a9afb2c9dbc3602cf25ab9a5f5ee1f991e6edfb9c2982a9d31cd7e41c2c9c2a8ad2a8da0c8943b54192c9fea120bf5cce390b459269698efaadb42d649'
    ],
    sigs: 2,
    script: '5241041ce544058996033a34adb07be380e63956c588dd036d20824447d88700ec91f45a98894bbbdab68ac304b5e68f77ea2f614516d0ace35f76e3b376b9917d6c844104db5efff14362653c0fc2e5437ac964dd3e093110c8fbcd5d9fd135ec3c98dc926d26b344def4397c3d99ebbd56e35c53cdd501e2c7a9a0cc5c2b04e7d0a3875141043b9264a9afb2c9dbc3602cf25ab9a5f5ee1f991e6edfb9c2982a9d31cd7e41c2c9c2a8ad2a8da0c8943b54192c9fea120bf5cce390b459269698efaadb42d64953ae'
  },
  {
    name: '8a96b8f4578bb00c6c201a857cd6f89cce878f345d5a5effec7349afb3589979/2 (p2sh, uncompressed)',
    keys: [
      '04fb716565869a8762671c4527a87d84ae56780c13f21b271191842eed94ec9ae7c55fdca0e12fcaa3c83141400e82d8abe7e2980d3b24f6ac702cece4562b8676',
      '042a0c86cf330e8baaa387a407bcb95e76f8ec1020d8a885dc7705cd3eef7f804cb3ee0eff434f6ac8efc0af2323d67b4af07058bb6d6d75afbab0521e47b55d66',
      '044a4687ceb6fe87176ce56717cbefb90c9760d2046dde130a4ea606f5b11c91991ecb083133c3b0e1ad2c5788b9f2d9988e8bd49c2b181245de4529e6c7a5c8da'
    ],
    sigs: 2,
    script: '524104fb716565869a8762671c4527a87d84ae56780c13f21b271191842eed94ec9ae7c55fdca0e12fcaa3c83141400e82d8abe7e2980d3b24f6ac702cece4562b867641042a0c86cf330e8baaa387a407bcb95e76f8ec1020d8a885dc7705cd3eef7f804cb3ee0eff434f6ac8efc0af2323d67b4af07058bb6d6d75afbab0521e47b55d6641044a4687ceb6fe87176ce56717cbefb90c9760d2046dde130a4ea606f5b11c91991ecb083133c3b0e1ad2c5788b9f2d9988e8bd49c2b181245de4529e6c7a5c8da53ae'
  }
];

describe('Script', function () {
  describe('createMultisigRedeemScript', function () {
    fixtures.forEach(function (fixture) {
      it(fixture.sigs + ' of ' + fixture.keys.length + ' (' + fixture.name + ')', function () {
        var keys = fixture.keys.map(hex);
        var script = Script.createMultisigRedeemScript(keys, fixture.sigs);
        expect(script.buffer.toString('hex')).to.equal(fixture.script);
      });
    });
  });
});