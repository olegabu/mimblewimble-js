const CryptoJS = require("crypto-js");
const secp = require("@vulpemventures/secp256k1-zkp");
const blake = require('blakejs');
const BigIntBuffer = require('bigint-buffer');
const BigNumber = require('bignumber.js');
const HDKey = require('hdkey');

// "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac031d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904"
const H = Buffer.from([
  0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
  0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
  0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e, 0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
  0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68, 0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04
]);

module.exports = class MW {
  constructor(privKey) {
    return (async () => {
      this.secp = await secp();

      if(privKey) {
        if (privKey instanceof HDKey) {
          this.privKey = privKey.privateKey;
        } else if (typeof privKey === 'string' || privKey instanceof String) {
          try {
            this.privKey = HDKey.fromExtendedKey(privKey).privateKey;
          } catch (err) {
            console.error('invalid extended private key:' + err);
          }
        } else if (privKey instanceof Buffer) {
          this.privKey = privKey;
        } else console.error('invalid private key: neither HDKey nor string nor Buffer');
      }

      return this;
    })();
  }

  newSecret() {
    return this.privKey;
  }

  commitValue(value, asset) {
    //TODO this is a temp fix. Need to blind the value generator H as secp256k1.Commit takes uint64 for value not big int we get from multiplying asset hash and value

    if(!asset)
      return value.toString();

    //// this gets correct result in bigint represented as string but is inconsistent with the result in golang where we need to cast to uint64 and wrap around.
    //
    // Here don't need to cast as the js lib takes string for value (may it wrap around later when unwraps into int from string?).
    // const assetHash = blake.blake2b(asset, undefined, 8);
    // console.log(assetHash);
    //
    // const assetHashBig = Buffer.from(assetHash).readBigUInt64BE(0);
    //
    // const assetHashBigInt = BigInt(assetHashBig);
    // console.log(assetHashBigInt);
    //
    // const valueBigInt = BigInt(value);
    // const resBigInt = assetHashBigInt * valueBigInt;
    // ret = resBigInt.toString();

    // this is a safe 32 bit int option with no native support for 64 bit as we're limited to 53 byte number
    const assetHash = blake.blake2b(asset, undefined, 4);
    console.log(assetHash);

    const assetHashNumber = Buffer.from(assetHash).readUInt32BE(0)
    console.log(assetHashNumber);

    const ret = value * assetHashNumber
    console.log(ret);

    return ret.toString();
  }

  commit(value, asset) {

    //TODO or use this.secp.generator.generateBlinded() ?
    const commitValue = this.commitValue(value, asset).toString();

    const blind = this.newSecret();

    const commit = this.secp.pedersen.commit(blind, commitValue, H);
    const commitSerializedHex = this.secp.pedersen.commitSerialize(commit).toString('hex');
    console.log(commitSerializedHex);

    return commitSerializedHex;
  }

  rangeproof(value, asset) {
    const commitValue = this.commitValue(value, asset).toString();

    const blind = this.newSecret();
    const commit = this.secp.pedersen.commit(blind, commitValue.toString(), H);
    const commitSerialized = this.secp.pedersen.commitSerialize(commit);
    console.log(commitSerialized);

    //TODO reuse blind as nonce?
    const nonce = blind;

    const rangeproof = this.secp.rangeproof.sign(commitSerialized,  blind, nonce, commitValue, H,
      '0', 0, 0, Buffer.alloc(0), Buffer.alloc(0));

    const rangeproofHex = rangeproof.toString('hex');
    console.log(rangeproofHex);

    return rangeproofHex;
  }

  verifyRangeproof(commitHex, rangeproofHex) {
    const commitSerialized = Buffer.from(commitHex, 'hex')
    const rangeproof = Buffer.from(rangeproofHex, 'hex')

    const res = this.secp.rangeproof.verify(commitSerialized, rangeproof, H, Buffer.alloc(0));
    console.log(res);

    const info = this.secp.rangeproof.info(rangeproof)
    console.log(info);

    return res;
  }

}