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
  switch (true) {
    case data.length < opcodes.OP_PUSHDATA1:
      buffer.writeUInt8(data.length, offset);
      offset += 1;
      break;
    case data.length <= 0xff:
      buffer.writeUInt8(opcodes.OP_PUSHDATA1, offset);
      buffer.writeUInt8(data.length, offset + 1);
      offset += 2;
      break;
    case data.length <= 0xffff:
      buffer.writeUInt8(opcodes.OP_PUSHDATA2, offset);
      buffer.writeUInt16BE(data.length, offset + 1);
      offset += 3;
      break;
    default:
      buffer.writeUInt8(opcodes.OP_PUSHDATA4, offset);
      buffer.writeUInt32BE(data.length, offset + 1);
      offset += 5;
      break;
  }
  data.copy(buffer, offset, 0, data.length);
  return offset + data.length;
}

function updateBuffer() {
  var buffer = this.buffer = new Buffer(byteLength(this.chunks));
  var offset = 0;
  this.chunks.forEach(function (chunk) {
    if (Buffer.isBuffer(chunk)) {
      offset = writeData(buffer, offset, chunk);
    } else {
      buffer.writeUInt8(chunk, offset);
      offset += 1;
    }
  });
}

Script.create = function (fn) {
  var script = new Script();
  fn.call(script, script);
  updateBuffer.call(script, script);
  return script;
};

// OP_DUP OP_HASH160 {pubKeyHash} OP_EQUALVERIFY OP_CHECKSIG
Script.createPubkeyHashOutput = function (hash) {
  return Script.create(function () {
    this.writeChunk(opcodes.OP_DUP);
    this.writeChunk(opcodes.OP_HASH160);
    this.writeChunk(hash);
    this.writeChunk(opcodes.OP_EQUALVERIFY);
    this.writeChunk(opcodes.OP_CHECKSIG);
  });
};

// m {pubkey}...{pubkey} n OP_CHECKMULTISIG
Script.createMultisigOutput = function (m, pubkeys) {
  var n = pubkeys.length;
  var NUM_OP = opcodes.OP_1 - 1;
  return Script.create(function () {
    this.writeChunk(NUM_OP + m);
    pubkeys.forEach(function (pubkey) {
      this.writeChunk(pubkey);
    }, this);
    this.writeChunk(NUM_OP + n);
    this.writeChunk(opcodes.OP_CHECKMULTISIG);
  });
};

// OP_0 ...signatures...
Script.createMultisigInput = function (signatures) {
  return Script.create(function () {
    this.writeChunk(opcodes.OP_0);
    signatures.forEach(function (signature) {
      this.writeChunk(signature);
    }, this);
  });
};


Script.opcodes = opcodes;

module.exports = Script;
