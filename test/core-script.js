var Script = require('../');
var opcodes = Script.opcodes;

var scripts = {
  // e2769b09e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436/0
  pubkeyhash: '76a914badeecfdef0507247fc8f74241d73bc039972d7b88ac',
  // 2ace0f550bdbace7c7ef0aae7876d241aba7816c3a225fc21111738629462071/0
  pubkey: '4104a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5ac',
  // 60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1/0
  multisig: '514104cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4410461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af52ae',
  // 9c08a4d78931342b37fd5f72900fb9983087e6f46c4a097d8a1f52c74e28eaf6/1
  scripthash: 'a91419a7d869032368fd1f1e26e5e73a4ad0e474960e87',
  // 6ea5c6f1a97f382f87523d13ef9f2ef17b828607107efdbba42a80b8a6555356/0
  nulldata: '6a2606706d409903a6b5dad3f703d00d03dbae5430a136f56d5c2dff7e5f18d12594b22558597cde',
  nonstandard: [
    // Scripts from tx ebc9fa1196a59e192352d76c0f6e73167046b9d37b8302b6bb6968dfd279b767
    '0101',
    '020201',
    '014c',
    '034c0201',
    '044dffff01',
    '014e',
    '064effffffff', // Too few bytes
    // Random junk
    '03630f7ed2f576',
    '4494c03f4786a2289d',
    'ec54dc118007b466c596066afdbd8764',
    '062058ea6e975ebdbad94b5e2acc8500c44f',
    '21d053e5a71bcde816e0da04feea36caf7ae489670e5951b4895d9e80d70df8ba0693cc8e55440c227eb102c6b804fb0edd5'
  ]
};
Object.keys(scripts).forEach(function (type) {
  if (Array.isArray(scripts[type])) {
    scripts[type] = scripts[type].map(function (hex) {
      return new Buffer(hex, 'hex');
    });
  } else {
    scripts[type] = new Buffer(scripts[type], 'hex');
  }
});

describe('core-script', function () {
  describe('parse', function () {
    it('pubkeyhash', function () {
      var script = new Script(new Buffer(scripts.pubkeyhash, 'hex'));
      expect(script.chunks[0]).to.equal(opcodes.OP_DUP);
      expect(script.chunks[1]).to.equal(opcodes.OP_HASH160);
      expect(script.chunks[2].toString('hex')).to.equal('badeecfdef0507247fc8f74241d73bc039972d7b');
      expect(script.chunks[3]).to.equal(opcodes.OP_EQUALVERIFY);
      expect(script.chunks[4]).to.equal(opcodes.OP_CHECKSIG);
    });

    it('pubkey', function () {
      var script = new Script(new Buffer(scripts.pubkey, 'hex'));
      expect(script.chunks[0].toString('hex')).to.equal('04a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5');
      expect(script.chunks[1]).to.equal(opcodes.OP_CHECKSIG);
    });

    it('multisig', function () {
      var script = new Script(new Buffer(scripts.multisig, 'hex'));
      expect(script.chunks[0]).to.equal(opcodes.OP_1);
      expect(script.chunks[1].toString('hex')).to.equal('04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4');
      expect(script.chunks[2].toString('hex')).to.equal('0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af');
      expect(script.chunks[3]).to.equal(opcodes.OP_2);
      expect(script.chunks[4]).to.equal(opcodes.OP_CHECKMULTISIG);
    });

    it('scripthash', function () {
      var script = new Script(new Buffer(scripts.scripthash, 'hex'));
      expect(script.chunks[0]).to.equal(opcodes.OP_HASH160);
      expect(script.chunks[1].toString('hex')).to.equal('19a7d869032368fd1f1e26e5e73a4ad0e474960e');
      expect(script.chunks[2]).to.equal(opcodes.OP_EQUAL);
    });

    it('nulldata', function () {
      var script = new Script(new Buffer(scripts.nulldata, 'hex'));
      expect(script.chunks[0]).to.equal(opcodes.OP_RETURN);
      expect(script.chunks[1].toString('hex')).to.equal('06706d409903a6b5dad3f703d00d03dbae5430a136f56d5c2dff7e5f18d12594b22558597cde');
    });

    it('don\'t throw on nonstandard or junk scripts', function () {
      scripts.nonstandard.forEach(function (script) {
        new Script(new Buffer(script, 'hex'));
      });
    });
  });

  describe('getOutputType', function () {
    it('pubkeyhash', function () {
      expect(new Script(scripts.pubkeyhash).getOutputType()).to.equal('pubkeyhash');
    });

    it('pubkey', function () {
      expect(new Script(scripts.pubkey).getOutputType()).to.equal('pubkey');
    });

    it('multisig', function () {
      expect(new Script(scripts.multisig).getOutputType()).to.equal('multisig');
    });

    it('scripthash', function () {
      expect(new Script(scripts.scripthash).getOutputType()).to.equal('scripthash');
    });

    it('nulldata', function () {
      expect(new Script(scripts.nulldata).getOutputType()).to.equal('nulldata');
    });

    it('nonstandard', function () {
      scripts.nonstandard.forEach(function (script) {
        expect(new Script(script).getOutputType()).to.equal('nonstandard');
      });
    });
  });

  describe('capture', function () {
    it('pubkeyhash', function () {
      expect(new Script(scripts.pubkeyhash).capture().toString('hex')).to.equal('badeecfdef0507247fc8f74241d73bc039972d7b');
    });

    it('pubkey', function () {
      expect(new Script(scripts.pubkey).capture().toString('hex')).to.equal('0568015a9facccfd09d70d409b6fc1a5546cecc6');
    });

    it('multisig', function () {
      expect(new Script(scripts.multisig).capture()).to.deep.equal([
        new Buffer('660d4ef3a743e3e696ad990364e555c271ad504b', 'hex'),
        new Buffer('641ad5051edd97029a003fe9efb29359fcee409d', 'hex')
      ]);
    });

    it('scripthash', function () {
      expect(new Script(scripts.scripthash).capture().toString('hex')).to.equal('19a7d869032368fd1f1e26e5e73a4ad0e474960e');
    });

    it('nulldata', function () {
      expect(new Script(scripts.nulldata).capture()).to.not.exist;
    });

    it('nonstandard', function () {
      scripts.nonstandard.forEach(function (script) {
        expect(new Script(script).capture()).to.not.exist;
      });
    });
  });
});
