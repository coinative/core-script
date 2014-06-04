var Script = require('../');
var opcodes = Script.opcodes;

function hex(hex) { return new Buffer(hex, 'hex'); }

var fixtures = require('./fixtures/multisig.json');

describe('Script', function () {
  describe('createMultisigOutput', function () {
    fixtures.forEach(function (fixture) {
      it(fixture.m + ' of ' + fixture.keys.length + ' (' + fixture.name + ')', function () {
        var keys = fixture.keys.map(hex);
        var script = Script.createMultisigOutput(fixture.m, keys);
        expect(script.buffer.toString('hex')).to.equal(fixture.output);
      });
    });
  });

  describe('createMultisigInput', function () {
    fixtures.forEach(function (fixture) {
      if (!fixture.input) return;

      it(fixture.m + ' of ' + fixture.keys.length + ' (' + fixture.name + ')', function () {
        var keys = fixture.keys.map(hex);
        var script = Script.createMultisigInput(fixture.signatures.map(hex));
        expect(script.buffer.toString('hex')).to.equal(fixture.input);
      });
    });
  });
});
