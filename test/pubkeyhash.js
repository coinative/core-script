var Script = require('../');
var opcodes = Script.opcodes;

function hex(hex) { return new Buffer(hex, 'hex'); }

var fixtures = require('./fixtures/pubkeyhash.json');

describe('Script', function () {
  describe('createPubkeyHashOutput', function () {
    fixtures.forEach(function (fixture) {
      it(fixture.name, function () {
        var script = Script.createPubkeyHashOutput(hex(fixture.hash));
        expect(script.buffer.toString('hex')).to.equal(fixture.output);
      });
    });
  });

  describe('createPubkeyHashInput', function () {
    fixtures.forEach(function (fixture) {
      if (!fixture.input) return;

      it(fixture.name, function () {
        var script = Script.createPubkeyHashInput(hex(fixture.signature), hex(fixture.pubkey));
        expect(script.buffer.toString('hex')).to.equal(fixture.input);
      });
    });
  });
});
