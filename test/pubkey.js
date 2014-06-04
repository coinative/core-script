var Script = require('../');
var opcodes = Script.opcodes;

function hex(hex) { return new Buffer(hex, 'hex'); }

var fixtures = require('./fixtures/pubkey.json');

describe('Script', function () {
  describe('createPubkeyOutput', function () {
    fixtures.forEach(function (fixture) {
      it(fixture.name, function () {
        var script = Script.createPubkeyOutput(hex(fixture.pubkey));
        expect(script.buffer.toString('hex')).to.equal(fixture.output);
      });
    });
  });

  describe('createPubkeyInput', function () {
    fixtures.forEach(function (fixture) {
      if (!fixture.input) return;

      it(fixture.name, function () {
        var script = Script.createPubkeyInput(hex(fixture.signature));
        expect(script.buffer.toString('hex')).to.equal(fixture.input);
      });
    });
  });
});
