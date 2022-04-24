const expect = require('chai').expect;
const MW = require('./index');
const bip39 = require('bip39');
const HDKey = require("hdkey");

const mnemonic = 'digital fatigue essay pretty number firm calm skirt exhibit seat able phrase';
const privKeyBufferString = '{"type":"Buffer","data":[123,96,232,99,210,241,102,192,9,123,208,224,44,120,255,230,99,254,11,146,51,81,222,127,116,235,117,144,198,195,9,132]}';

function getTransactionPrivateKey() {
  return getTransactionPrivateHDKey().privateKey;
}
function getTransactionPrivateHDKey() {
  const masterKey = HDKey.fromMasterSeed(bip39.mnemonicToSeedSync(mnemonic));
  const childKey = masterKey.deriveChild(0);
  // const childKey = masterKey.derive('m/0/1');
  return childKey;
}

describe('MW', function () {

  describe('#constructor()',() => {
    it('should return new instance of MimbleWimble library with no private key', async () => {
      const o = await new MW();
      expect(o).to.be.an('object');
      expect(o.privKey).to.be.undefined;
    });

    it('should return new instance with a private key given as HDKey', async () => {
      const o = await new MW(getTransactionPrivateHDKey());
      expect(o.privKey).to.be.instanceof(Buffer);
    });

    it('should return new instance with a private key given as extended key string', async () => {
      const o = await new MW(getTransactionPrivateHDKey().privateExtendedKey);
      expect(o.privKey).to.be.instanceof(Buffer);
    });

    it('should return new instance with a private key given as Buffer', async () => {
      const o = await new MW(getTransactionPrivateKey());
      const s = JSON.stringify(o.privKey);
      expect(o.privKey).to.be.instanceof(Buffer);
      expect(s).to.be.eq(privKeyBufferString);
    });

    it('should return new instance with a private key given as Buffer', async () => {
      const b = JSON.parse(privKeyBufferString);
      const o = await new MW(new Buffer.from(b));
      expect(o.privKey).to.be.instanceof(Buffer);
    });

    it('should create from an invalid private key', async () => {
      const o = await new MW("lala");
      expect(o).to.be.an('object');
      expect(o.privKey).to.be.undefined;
    });
  });

  describe('#commitValue()',() => {
    it('should return a product of value and asset hash', async () => {
      const o = await new MW();

      const commitValue = o.commitValue(value, asset);
      expect(commitValue).to.equal('9652291107');
    });
    it('should return value when no asset is specified', async () => {
      const o = await new MW();

      const commitValue = o.commitValue(value);
      expect(commitValue).to.equal(value.toString());
    });
    it('should handle MaxUint64', async () => {
      const o = await new MW();

      // this is MaxUint64 in golang
      const commitValue = o.commitValue(18446744073709551615);

      //TODO returns different from golang's wrapped around result 18446744070492121247
      expect(commitValue).to.equal('18446744073709552000');
    });
    it('should handle MaxUint64', async () => {
      const o = await new MW();

      // this is MaxUint64 in golang
      const commitValue = o.commitValue(18446744073709551615, 'cash');

      //TODO returns different from golang's wrapped around result 18446744070492121247
      expect(commitValue).to.equal('18446744073709552000');
    });
  });

  const value = 3;
  const asset = 'cash';
  const commitExpected = '09b61a56c3033c1fb424f2f748acc4812b22c09a26d3c57cd9bbf9a29dc1c495b4';
  const rangeproofExpected = '403f7582c85ced265b52a27aad9107ce03b1845e3ad4808cbf9704487000726dd19c4f65249a90aff44889784b74ee3270641124ccb8d1a2de989d8438ab799279f7a3ddfb038113d2d6988753d55dd1102a1a17ecdf7a01577ebf752acb65738b60af3e52571a35867925f1993b508e73fee309844b6ed6005b3d494234a093c35ddc347e101916216473bb41733b455788bcef22c6b0a7422c1aa385843dbac34b931ee5dd48946b8951df36bc0e48ef194d7c02fa1d0da095b5ebbdd8f4c43aec023b16723202ff8757215ee7ee14390337ff4e1bb6c25a47ba1e5561a4f6ede5f424f1c6fb15ce381f7d170253921c585de6aaef4407839f6d385d0f2c22ffb882f7a66ced69bfacd0f10a2a874b5a573ba8480618bea9df81b4290ed475c035572eade6ae9b3b63791f24ebc9d313af1e6dbf8311217208f7ec7a762e4c55d202fc1b6fd9926c22141104069b88523158c9c9e054d8b9a51f3a959623150a0b16b6b48d463470860bb9cd42345f5e40dbe607f845317b26d96ca58123b3d162b157f0810f10fe3c9f6b3509fe99659065137d5b2f4b6fd5a43332da5dc4a2afb554a1ce1c0b0584b4c5df919099c105c4fb289c7da8726d9021dbf6060c1705487531e6c46b6b83797ea0d48fba126540f196e1ada49cb6e306cd26dc2dd994cbbde806353b75c9806e9b93b9e071bee92fbc042df483faa7ed1f2e4e3a090f70bd924ddae1a472808d0533732a8f40bcdb375419f1fa6596428ee49b17e5bd816b9be2b1dbca77c1a58d2993cf9491787ff8a4e862af9129567a8d8a54ce56f26004dcae6856ed5858a93ecdce1c83389de6eb57d4217234780a980c1dfa7db51e7a0de1c88be1b026868f17b8cf3253b5a50f8a6eafd492a0ef8de509ca8eb23f4ddd886c396a8786c419cbaedfbe1c5528317a3d61c9583b9fcf5b3c3f870293fc082ff6dfea6d2e56397e1d11e91265ec14dec4f675cd83d860f49e57ca6d36839ee0a9bf7b995641990d04adc21833330769a7290b198e8dff0940757909017700cd3f597ee3b9b3698f246a967d3346cfe4238d8100542d0f12ca522fbbf8b9175f1d56054fc86acb45516972425f7092889f3ea1b4621612a52caade71bb732439fc7a294a08dbaea7aa38e8b4063d553bf77e699f76d63bd9611341cac0eb45b0e8c1629c5cf9a9b1857088b40c01209e02fce9b0bdb6273356ae38f1dd5735df96d838f0d65a1813fc40b0d2ea5cc53568d0f1b7f9abca346ca2b37f0681791f559bd29c99da81ca75d8bb7cda325c6ebff3dbf7b26d5373710b645923d5d40317e893786a3cd88bbe7b478a8f31772d2d865da04582736ebdd31b02752346ae1dc6692265999296ee725749cfa144f1417ccafec75418f3f72ca5ad5581a77e49a5ff06a7752ad5fb580e8b1fe3d469fed181e6a90e4cff77e4747be8839f61434cb76698fc778bf9f09d536f180eff00497ccbcd01f4305ea6371cfde638e8a41f3c238da425ee085826b8c97c928126295ac518d8bd9975c62f6529bed2f5c2925fc3ad39fadd4f77cf1fa357e8b33bdfd2025d12a0f97515221b7d47f5044807a53711e9222bb0bb954de9a71a263e777950911c6e514b09836f2a9741246244b0e8336ec5c5a4641f4c82259d6a8e3674716f1ad8a322c956499d9346f03f5b971eb3673db40ebdf7675320a7fcd88cf76be1ba2d6abf8268888d07a4654883828b99e1d642bcd2a3f4fbe11204ab6e040030424806dfb47f57818732b26d94a73463f4713dd7d81144741e8d140d050918ffaa00a215aeddedefaaf0e9f1b36a9c340ac90cb6a1d78448bc47e527af957ccaf3e41072f770480a2b7e3de2b9251fa05b5c3dbe53e529d6c5b03996e0a432486fb852492df1624419d597c33c59d266b2ef3802da53a3b348f61cc52d4bce3d1f5e9a666a28daa4719cadc7ef0175945a0c2cb57e437db2e5ec10422ab51604586d9b9da061c1f4db9052b8d33050858752967f6132656c659af7b8598116aa6079729a9feea99a94742079719dba1aed25f932cba33c2ad6d7f93a4d8f1094d64a59e5dcbe225cb19c34ff0936f7fe4857656e24586a1913b7ebe9ca53e3316cca7c8c4eeab05d4b3f7b2a38362a50681607e059969bf5f09e23f1fdeafad4a5410f35aa9f79cf680934fa85af356efb9793e697353d111ca684b08d25e6ca4e99d86fb9a09ddcfc67ed02f6e320e8279d54127b581fecbdb6d3620c8ffed71aa8e63be797b15c1122f5062c7d5b56f2996e505bb41ea686a87986e64549c684a3e59d481820edeaea1ddc5c32e2fa357fc6cded3c419de1d9fe88fe532bae6dddece46c971d6655820b1c93e579ae16d884671bdbe89974f549e9de93b7a165d2cf3e6e4b2378e4189d69af13227abb19bca31c749629d84d2340b52e18a0383f656629ec35db1857d87d005754a2b200542a84c39b0a15d4f75387511e1530d44109926e4eb30c4c76458a88bf7f5c1770dc713142ba26eeb8eeb39cee3cd3dd6953b87f680e6427d485cec84af0d97ddef83122ccf400f1f28a470cbe8db5a3fee9b46af430e1d02b8ad1beb8884f2304771180cae0401d0c122e367e1c98e9b85d144ebb1bfb790cbbcab0145b93cf4f798d348ee880c5f44eb132f9d3848a01395df5c66be780777625c06fc76bd62ad93ccd003935d8c8b17d76a2d00d78ac83c877f3570be34c105fa27e7343d697b0da1e9cf12b4f1fbd5b571bdb6b53a096d6f91c1e7d05a91c6bc8861745f02ed7e824c3185ca29d71d055cc9161085035dd52bcd81a9bdc69e30efe9221f847ae2ca93a7f8c609ecc32147d7c7457df5e84971ee8e67dec745b70de09434e560532646eefbf6fb4c92b40d4f56d0578421d9d9068d3806e2d1b4c1a4e8ba743f5c578d5a34545c50de3a9d94e9f7695fd73b1ea68a1d2582c914bdaf7fc7a8f88dda43ecc1f7ccc1392c1e91059e1e87addb543f8fae88d511248644749d7c7deeca27da7acd7208406f9f6e16cdea8097c66eb2e21cb287ff921db54d063b31df12b4db1fa220a118f0799774694112d5c2052a021e4ed35c2cf0aa2cd345c603005a8ca68eb30d9c0c0bce726110d066c24f8507a5438831611299a041262796535448db2b4f7f5f4dcab1f51936a544a8b19f1395dca18ae6908469b8d9d3a0d777cd505c90ecb23eb0e3182f4a61740d78ec718b26565141eec3a206c762ad8fddd280d9ab5ca909f77509c0aca379b6a88c070ea5b2903925f80e42eec0fa3792496154024e1d2a20c5b3d52989ae42c98e635cb7a0ffc6007757bf31d1aa5a0be8385a421459f02d50081b266797acb802400981d2fa02a4b606778f13c8e25e4cfff7d1e609bf0f9cb3b601e4238a95d10e6318183f789c821a73cd2f6356d2b7c24db63eea81a055cbe84f3cca72999bc05e082be33b1fec56f8e26f03d4c010b3dac048fa06f3e5607b4030b6ea3a6014a43a1517c4d75f4e8b83f5af21b3d2a79e3f2b7c431d785f22b7843e698b916de1c47bf48611093e1152c94056e4d30fba4e2f0d4aef597c6e040e2117a5cdd76c24bae6be4b44f3ccdb5b8ef9a2f775a2cecd08facb333a7d22817b7757f9a92f4c2bd9049fa0830355958ed1563f56ba128d61dbb86efb1bfdf3bbb96725ac3ef7e5b68c8e77b458507fc3c3c2ffd02ddd0204af24c534732c04d6c436da9c287a5b3afc77a40cf9f8105dbe5a9c83955a5b446cf8712b23bf03cb88914692e81c53ce9a9e43192bae201d6f4b4ec448ce0e7bf2e70f44d0c25585ffff7e0137654f6bde9752f2c5d3b97342be0b40629a075d29cdecf7bab995a2ce1ded0dda83aa2f8f1ac7910393739f90d02b35ff0b4a4a1da965e10cbe06ac4cd092a4e313e1058012517ffa68a09b75148d65d6abd75dd5de6f318fafca0a6e8ea7e45079fb5793a08b54df0dcfd9f4a89f0de3d070d01fd0d8f923b923285a418a6563e54e090d1c18fac80e9c7e498c7e1a8495678fabec144ebf693f860bd4ff379e69c501f93fc5ed4675015d5c6a50a781d9d732afba6c0d3a4792f65988ce19f434fe2dca2a6ddbb84734fcf806a734d7bfe200eb78e333f8d83790e40996117b0cde9a1dec3b6f1ee5fc80815356f5fd6909e0cb3387935f93fec5a26986e4d57efc0a48d5883b0733a19668ff8ca616ee40fc98484941abc5781b413960d55cc72ff3336a773e6d74888babb971d03d51b3421255b969237bb47c921df8d1d7b890b0fd701a78ecada7c7d7363105ef4a2e8282713776a5a51f65d1d4badea90f87761da54b10d6d79702062b13c0aabfaae2ce37a4565c3779382d07d4f250a20b2972e28f0b23d668c1552a6c25ac6adf6af9cff9239aa82016fe885e1bc6a83e85b6da557c332868dde7c8db025955677899a218fa84171049b039295cb691b4cadf508519e488e47bbbdbf7a229965323a9c478fda4131e092f5177147d6628ab78cd4a071253cd632eb51871cccd43e50b49a8fa40447c29f55bc77138a5f2a0ee78024506896d3ce8159d295c633a5dbfb298e10db6e6e92218a113fa8650ba2558c6236f2067e8ab51e9296eac7bedb83a9aded284bff865c7e2496ff1d8f5ecf06a9cd23c57f5ceb90a2a3f960d762a7b7cfbb8f29c19d62867e9539cf6eb2402c189c3b697de5fbf6128480214da1d41ff6802ba8a5f5c6d10f0e877d7947856ce4a41471281329ec283f2c9e0c422ab39b20b058718f03d48c3f0c37c0f164e4d35ff7523552b9c7d331e2dd2031d1737d5cd365fb56f24e40a3989086b6cdba7a66342c622e4e13488a9feb3a42c1d751c3d6e1f31761434918aa71bf5afbd13d07986332d1ea9742b10a281228de4be4473daf1ad1cb79146f65fcba3f81a589fb32edc2ff2f714531ebb793fc66c91e3a48b12b25980b41f4d990841f18df05325b2a0f373a2fa77765cbf4919350869b859456ce66aa75f175e26d2481ff18b71338407451f763cbe7e2e079f85c351d6541f5f4c83d8486318d82f413aea2a86a9c4545575f2296348b24a461a1b26b4543111a8f0d4ba5cd3f4a79484a4a1004074f1373885c46ad2c779c69f4c2e8525508965c1bb2aa8a53aa132268108e7efa2d8359bf07f0376478e0c9fafb43ffa793447a674a43f20c9f8bf2c6a01cc49cb7400671d0a2ba4cfb5cffa2d016e529c67d51fbf6f6e7830a9ebc8485ad65843696160e3b7cf159ddff3b68f4c2d979477142ef06cc7057d301fbb28f14cd1964b65c5d0d649415d73db896c30e4f400f314bde343a211b8d28e78a1abcb56eae073eea1a5b7ebec94d74a4fafe391083a4ea32984d445d52b634adb34439935b3b1661044c672f86b978024f8ec245d0fb427d9e5febb8a3880fe17b44dbb9e55f012c0afb370eabe3c8e4b0315584ab1b4655ccb4c65ac652299104a120d0a5dacfb27b8813b342cc0ef429c4c53a4eec365c435d938ff971c9cd6da3b41a6cc4295766b614e7881e0b3824c08eacc60b2fcbddb79bc4f692942415e824db9bc7806c0c3b6af1826139b6405933bdd7ea8d77f781f2322137e10831c0aa51e43f43181a70faf163d89947089835e3a44c505caabaafd45028fc050aa0d374a7c81eb9ceab27c6a27d01699049646de8ff41a23757b62a82d4b42730c0270f431c10a1506d02fbf041ae30e37945161275edc774d981ecfbf077246556971ad770682726d93017cde8324b65f02fd46dca3ec02e0fca530e9bf0a0cf558c334a66a3c903fd9bcfbf9d644a6d3c26787f79e2d9a1bf7b726cf5210f1f1b7df5b189dc197d1ccdf1e14984091b841c19ccb8224f7c076cab01367373d5bac3b09b2aa6906c341d5a1d4e9727a6d009933c7b378ba64ce76bde3f4ea564f401e2c5a2c3042771858e92fabe4139239388c78188012739ae5e52e91ffd2c01f00e79e3d19d6a87a58a6b2d7da3e5134d9e6b6ae71c088a03e29f463c09acee506cd457ef390db38d8c413a9d314a7d637ed70fef5179a4a220284d3425e472e5ed42185463f10051e98f151056ccdf570d43bda0515903879f240abfb7f883b0d865a19d16b74309cf7aaef47627cbca0b020de0b1cbc725a923f8f421780b076aa62a476af843046bc2838141cd3b98132083c4fc7d0b350846dbc889d4fd34b4436ba1c8b0d2ded9d982d4e96559ea71769957b3180bb0b1651d82df6c3b64533d4675144496cea54e931631eefc5203433f0fb9a498e3ede839eb555a41b564811ad16cb2ad7e56d78b7d12149f4ed0ab449a61c868a76a5f2933613680a55075603aff6b7b25e89bf3236ec454896a13c44d7f048af5d101aa43ff165cadb7e356eaa3ff7f3388c61f4d2befd174457109f721c2049e6968ce38f3c7b92495d20d5f1a7024cf916c9211dafe4ff21a63448900736b321d7dd718fbdabed05c104eb75d7a1b46ba0b840c3dc941e9e5fd64e64fc39a70f9f694f1bd6664ab996c27b22469249ee05b3735bbac95076e183c1e795b428aa508640ec7f851dfae3aea90cbd8aba5cef3b0aa1424e70d35684380c35c7e55b3824f7a85ec31e35e53a7c3c1257903388a658a70c8e4db0978374983e8533f01fb9d9085a9ab2897fcac97082689ff48f61e50239bb2fb771d034e3cba0096349bbe314128cffb58e5cb5974dde847c9efa69939884efd75ddd8fa568b41dccdd61c1c9213c78dd386469bb580210365e36dedee040385ad2332926b7dc5ca9ab493a9523f6767030a1e751654fa0f55ae369ad68217a44e52f3c86af6c07ab5cbe3e85f5446924b051fdfbea86ec0a79088ee5df30d3a10077050d92f58b3b2261e3e0241c85baf0b2a87daf1b6d1f4e24e03dd7728374a788956dca19177c6ece300a3401f8ddadec7197f48956e9bb8832e7773d5b9429cb3b3ad1283a14399ce82449d6488cd0eb6b2de300f792165ba853053632f9e9a4f9140f3c810bd60572671a5f447dac79faf94711488e3b2f7c37cfcb193f025c9523d45a1a9d665fccc5e276bd01704fb090cbf0a9179faed5e538ed85d08bc98699a6daef3ac496ca10541b34aa9d0ede892b512a9c84639543621ba371ab7ee0c0d491e27a6839be1d2016b595533d732d11e6382c0afd4e30eb8a63ca4280f09cf4a5ae7a3fbf463ca66fe47b6eb9800d55e78db02dae27e2741af5258c8e26b46cc9e86d4b0f526bfd5ba3e2468d7de9deecdee141b576880720d5c5073233e77183404';

  describe('#commit()', () => {
    it('should return a Pedersen commitment to a given value and asset', async () => {
      const o = await new MW(getTransactionPrivateKey());

      const commit = o.commit(value, asset);
      expect(commit).to.equal(commitExpected);
    });
  });

  describe('#rangeproof()', () => {
    it('should return a Bulletproofs range proof that a given value is greater than zero', async () => {
      const o = await new MW(getTransactionPrivateKey());

      const rangeproof = o.rangeproof(value, asset);
      expect(rangeproof).to.equal(rangeproofExpected);
    });
  });

  describe('#verifyRangeproof()', () => {
    it('should verify that a given range proof is valid for a given output with positive value', async () => {
      const o = await new MW(getTransactionPrivateKey());

      const res = o.verifyRangeproof(commitExpected, rangeproofExpected);
      expect(res).to.be.true;
    });

    xit('should verify that a given range proof is invalid for an output with negative value', async () => {
      const o = await new MW(getTransactionPrivateKey());

      const commit = o.commit(value * -1);
      const rangeproof = o.rangeproof(value * -1);

      const res = o.verifyRangeproof(commit, rangeproof);
      expect(res).to.be.false;
    });
  });


});
