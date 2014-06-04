var assert = require('assert');
var opcodes = require('./opcode').map;
var hash160 = require('core-hash').hash160;

function Script(buffer) {
  this.buffer = buffer || new Buffer(0);
  this.chunks = [];
  this.parse();
}

Script.prototype.parse = function () {
  var offset = 0;
  while (offset < this.buffer.length) {
    var opcode = this.buffer.readUInt8(offset);
    offset += 1;
    if (opcode <= opcodes.OP_PUSHDATA4) {
      var length = opcode;
      switch(opcode) {
        case opcodes.OP_PUSHDATA1:
          length = this.buffer.readUInt8(offset, true);
          offset += 1;
          break;
        case opcodes.OP_PUSHDATA2:
          length = this.buffer.readUInt16BE(offset, true);
          offset += 2;
          break;
        case opcodes.OP_PUSHDATA4:
          length = this.buffer.readUInt32BE(offset, true);
          offset += 4;
          break;
      }
      this.chunks.push(this.buffer.slice(offset, offset + length));
      offset += length;
    } else {
      this.chunks.push(opcode);
    }
  }
};

function isSmallInteger(opcode) {
  return opcode === opcodes.OP_0 || (opcode >= opcodes.OP_1 && opcode <= opcodes.OP_16);
}

function isSmallData(chunk) {
  return Buffer.isBuffer(chunk) && chunk.length <= 40;
}

function isHash160(chunk) {
  return Buffer.isBuffer(chunk) && chunk.length === 20;
}

function isPubkey(chunk) {
  return Buffer.isBuffer(chunk) && chunk.length >= 33 && chunk.length <= 65;
}

function isPubkeyHashScript(chunks) {
  return chunks.length === 5 &&
    chunks[0] === opcodes.OP_DUP &&
    chunks[1] === opcodes.OP_HASH160 &&
    isHash160(chunks[2]) &&
    chunks[3] === opcodes.OP_EQUALVERIFY &&
    chunks[4] === opcodes.OP_CHECKSIG;
}

function isPubkeyScript(chunks) {
  return chunks.length === 2 &&
    isPubkey(chunks[0]) &&
    chunks[1] === opcodes.OP_CHECKSIG;
}

function isScriptHashScript(chunks) {
  return chunks.length === 3 &&
    chunks[0] === opcodes.OP_HASH160 &&
    isHash160(chunks[1]) &&
    chunks[2] === opcodes.OP_EQUAL;
}

function isMultisigScript(chunks) {
  return chunks.length > 3 &&
    isSmallInteger(chunks[0]) &&
    chunks[chunks.length - 1] === opcodes.OP_CHECKMULTISIG &&
    chunks.slice(1, chunks.length - 2).every(isPubkey) &&
    isSmallInteger(chunks[chunks.length - 2]);
}

function isNullDataScript(chunks) {
  return chunks.length === 2 &&
    chunks[0] === opcodes.OP_RETURN &&
    isSmallData(chunks[1]);
}

Script.prototype.getOutputType = function () {
  switch (true) {
    case isPubkeyHashScript(this.chunks):
      return 'pubkeyhash';
    case isPubkeyScript(this.chunks):
      return 'pubkey';
    case isScriptHashScript(this.chunks):
      return 'scripthash';
    case isMultisigScript(this.chunks):
      return 'multisig';
    case isNullDataScript(this.chunks):
      return 'nulldata';
    default:
      return 'nonstandard';
  }
};

Script.prototype.capture = function () {
  switch (this.getOutputType()) {
    case 'pubkeyhash':
      return this.chunks[2];
    case 'pubkey':
      return hash160(this.chunks[0]);
    case 'scripthash':
      return this.chunks[1];
    case 'multisig':
      return this.chunks.slice(1, this.chunks.length - 2).map(hash160);
  }
};

Script.prototype.writeChunk = function (chunk) {
  this.chunks.push(chunk);
};

function prefixLength(length) {
  switch (true) {
    case length < opcodes.OP_PUSHDATA1:
      return 1;
    case length <= 0xff:
      return 2;
    case length <= 0xffff:
      return 3;
    default:
      return 5;
  }
}

function byteLength(chunks) {
  return chunks.reduce(function (length, chunk) {
    return Buffer.isBuffer(chunk)
      ? length + prefixLength(chunk.length) + chunk.length
      : length + 1;
  }, 0);
}

function writeData(buffer, offset, data) {
  if (data.length < opcodes.OP_PUSHDATA1) {
    buffer.writeUInt8(data.length, offset);
    offset += 1;
  } else if (data.length <= 0xff) {
    buffer.writeUInt8(opcodes.OP_PUSHDATA1, offset);
    buffer.writeUInt8(data.length, offset + 1);
    offset += 2;
  } else if (data.length <= 0xffff) {
    buffer.writeUInt8(opcodes.OP_PUSHDATA2, offset);
    buffer.writeUInt16BE(data.length, offset + 1);
    offset += 3;
  } else {
    buffer.writeUInt8(opcodes.OP_PUSHDATA4, offset);
    buffer.writeUInt32BE(data.length, offset + 1);
    offset += 5;
  }
  data.copy(buffer, offset, 0, data.length);
  return offset + data.length;
}

Script.prototype.updateBuffer = function () {
  var buffer = this.buffer = new Buffer(byteLength(this.chunks));
  var offset = 0;
  this.chunks.forEach(function (chunk) {
    if (Buffer.isBuffer(chunk)) {
      offset = writeData(buffer, offset, chunk);
    } else {
      buffer[offset++] = chunk;
    }
  });
};

Script.createMultisigRedeemScript = function (pubkeys, sigs) {
  assert(pubkeys && pubkeys.length > 0, 'Missing public keys');
  assert(pubkeys.length < 16, 'Too many public keys');
  assert(sigs, 'Missing number of required signatures');
  assert(sigs <= pubkeys.length, 'Number of required signatures cannot be higher than the number of public keys');

  var baseOp = opcodes.OP_1 - 1;
  var script = new Script();
  script.writeChunk(baseOp + sigs);
  pubkeys.forEach(function (pubkey) {
    script.writeChunk(pubkey);
  });
  script.writeChunk(baseOp + pubkeys.length);
  script.writeChunk(opcodes.OP_CHECKMULTISIG);
  script.updateBuffer();
  return script;
};

Script.opcodes = opcodes;

module.exports = Script;
