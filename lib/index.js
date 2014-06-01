var opcodes = require('./opcode').map;
var hash160 = require('core-hash').hash160;

// Worth it for cleaner code
for (var key in opcodes) {
  eval('var ' + key + ' = ' + opcodes[key] + ';');
}

var MAX_OP_RETURN_RELAY = 40;

function isSmallInteger(opcode) {
  return opcode === OP_0 || (opcode >= OP_1 && opcode <= OP_16);
}

function isSmallData(chunk) {
  return Buffer.isBuffer(chunk) && chunk.length <= MAX_OP_RETURN_RELAY;
}

function isHash160(chunk) {
  return Buffer.isBuffer(chunk) && chunk.length === 20;
}

function isPubkey(chunk) {
  return Buffer.isBuffer(chunk) && chunk.length >= 33 && chunk.length <= 65;
}

function Script(buffer) {
  this.buffer = buffer || new Buffer(0);
  this.chunks = [];
  this.parse();
}

Script.prototype.parse = function () {
  var offset = 0;
  while (offset < this.buffer.length) {
    var opcode = this.buffer[offset++];
    if (opcode <= OP_PUSHDATA4) {
      var length = opcode;
      switch(opcode) {
        case OP_PUSHDATA1:
          length = this.buffer[offset++];
          break;
        case OP_PUSHDATA2:
          length = (this.buffer[offset++] << 8) |
                    this.buffer[offset++];
          break;
        case OP_PUSHDATA4:
          length = (this.buffer[offset++] << 24) |
                   (this.buffer[offset++] << 16) |
                   (this.buffer[offset++] << 8) |
                    this.buffer[offset++];
          break;
      }
      this.chunks.push(this.buffer.slice(offset, offset + length));
      offset += length;
    } else {
      this.chunks.push(opcode);
    }
  }
};

Script.prototype.getOutputType = function () {
  var chunks = this.chunks;
  if (chunks.length === 5 &&
      chunks[0] === OP_DUP &&
      chunks[1] === OP_HASH160 &&
      isHash160(chunks[2]) &&
      chunks[3] === OP_EQUALVERIFY &&
      chunks[4] === OP_CHECKSIG) {
    return 'pubkeyhash';
  }
  if (chunks.length === 2 &&
      isPubkey(chunks[0]) &&
      chunks[1] === OP_CHECKSIG) {
    return 'pubkey';
  }
  if (chunks.length === 3 &&
      chunks[0] === OP_HASH160 &&
      isHash160(chunks[1]) &&
      chunks[2] === OP_EQUAL) {
    return 'scripthash';
  }
  if (chunks.length > 3 &&
      isSmallInteger(chunks[0]) &&
      chunks[chunks.length - 1] === OP_CHECKMULTISIG &&
      chunks.slice(1, chunks.length - 2).every(isPubkey) &&
      isSmallInteger(chunks[chunks.length - 2])) {
    return 'multisig';
  }
  if (chunks.length === 2 &&
      chunks[0] === OP_RETURN &&
      isSmallData(chunks[1])) {
    return 'nulldata';
  }
  return 'nonstandard';
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

Script.opcodes = opcodes;

module.exports = Script;
