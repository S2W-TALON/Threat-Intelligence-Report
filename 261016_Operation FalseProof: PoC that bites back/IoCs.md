## IoCs for Operation FalseProof: PoC that bites back

---

### File hashes

| MD5 | SHA256 | Type |
| --- | --- | --- |
| 3b745141298cfeea3aff01034579bf19 | 8d1f03e9022525b03e9e27b8924b695891a024d94381e4bac3110ded8a8c4b1c | CoDawnloader |
| f7d58d139b66c740f450e2bf79f2704a | 93eb736a6e493218c3ca60df99eabcd73adbf5b42ef32e569e6aa3d8a3d37f66 | CoDawnloader |
| 2ce45c04f49c542118466c264a8d01da | 26c8217caeebd4318fc840e5bc419b8971696616bd512f1d9a1c4660d0c2b6ae | CoDawnloader Payload |
| 9c33e69f894caa34af567ef639e49ef2 | ec00dd503dd7195bf6243076f040f833b12e8833695f5a5a98414bb92b43d3bd | cryptography.pyd (v1.0.0) |
| b5129718ebb8469a1a27bd0aed34eb5f | fa037083673577fd9c2d341ef9fd7bd53531436a2fea24164523067244498814 | cryptography.pyd (v1.1.0) |
| 02467ff4429cc31fe38c797c1381171c | 511831d10811aef3503332497f0a71b4e82fa1673892bddf7ecd5340e48d1774 | cryptography.so (v1.0.0) |
| 9c33e69f894caa34af567ef639e49ef2 | ec00dd503dd7195bf6243076f040f833b12e8833695f5a5a98414bb92b43d3bd | cryptography.so (v1.1.0) |
| 2124ca8cba69568ed9933ac2bdb53a35 | 728f8250380f951303433bd1c35a173043ef4367230ad8fbc8722ee823a43947 | encrypted https.py (v1.0.0, pyd) |
| e43824f3afe7635e46328099eb9966a2 | a5bc8931a28dadea0958630b98ec5672eabe78d62bc30db83ef6b799fbc2e4dc | encrypted https.py (v1.1.0, pyd) |
| dc47b91459dfe56d4149fe0ecb9c5b50 | 69fd267a2ec24a21b5645746abb25e7cb38a2723d1c1a9e79c1e19eec9f11e35 | decrypted https.py (v1.0.0, pyd) |
| c0282911610694469a824d22e41528f1 | 35057d9f7f983f4fbdff4103dd1091fb489c3f8416ff5d7278df3314245ceadd | decrypted https.py (v1.1.0, pyd) |
| 4542b85c5a87abec22b06d5119f13fa1 | 9d5673ee877a0a272acc25d1c70e4b237a765ba5c7ff242b86a9edf45e4648b1 | encrypted package.pth (v1.0.0, pyd) |
| f89c901e3ccefdef034e3b89348ab74c | b15852e2077b81e23bd59dd57d29fea0216467dbc9c150eadc9170f98f50c64c | encrypted package.pth (v1.1.0, pyd) |
| 671aa9340375541b26bbce1fb0b0ca8d | 919c30dfc8990eceaa2a4ad09e604d25bcf4b79bbdfc05edc5db97528f485cfd | decrypted package.pth (v1.0.0, pyd) |
| da214c5e4e57f53ea808f47bd49b0d01 | 916d7f7d79edaae71bbe62a32b1972d6957a4cda2b0a3a0ed084b818b9cf387e | decrypted package.pth (v1.1.0, pyd) |
| b3366f9e82e776f70e417d1b8c894f38 | 0fc8812616069485eab9ad8e3deeff8c969cf5e727b67eeeb357ca0b10b87a94 | encrypted https.py (v1.0.0, so) |
| 0dd99040a0b0b3db5df67707574725a7 | cbb6e2e62744e8b099ab073fc506604ec27a20cd02e3c4ac6130d6cd6c437def | encrypted https.py (v1.1.0, so) |
| a0ecc642cea4f50eb83ce8896888c19e | ff9fe722d320f986ace57ddec86e13941d9e4f990179f7bd9636b01432e2dfc9 | decrypted https.py (v1.0.0, so) |
| 0576bbbd5a10f740d4066517777c8311 | 5cb0d8f8b8061cf56ea9ecd2a94620f7148dffb137ea42fdf3a0a24c5be1ba3c | decrypted https.py (v1.1.0, so) |
| 8129c6aab9255e7e9d730b21608c98d5 | f737cf6f98deacd0786a1608e7297e92d7050c27c47ca9bb14f384a420a874ff | encrypted package.pth (v1.0.0 / v1.1.0, so) |
| 15e5c81497703c570a195c0144c444d8 | 9635d03fcfd04adc57818aa13262e7e4df357df5f0d47cd4b083a15a5589b100 | decrypted package.pth (v1.0.0 / v1.1.0, so) |
| 0130a2ab62d72b31116b1fd6b3c45ed7 | 84cb219bfcf69f6207c1174537d9c1018152ca0781ddb1d3fe4103b18c69d972 | SporeDrop |
| bfd032d4c00115b197af6f020f27f34e | de3bec5960a366b7c2f5e1b63a46b2eb63e8d31ae5a6ac18b0ed4216a04bf876 | slogsec 1.0.0 whl |
| fdf3e1f733c78a26599c57515f392af0 | e96c98d4e0acc684982195f31908196eecfcda3b4c5b8db34d357c6c6349f008 | logcrypt 1.0.0 linux whl |
| 555ecbba5bcea320ce794a268dea0ebf | 17e9ab4725db06a59d1f3df874757ff65c2775efc1bbdfc24bcf3c58f3a245ce | logcrypt 1.0.0 win whl |
| 3ed51b7c048f926f2f2f92b4566e9289 | 0e973e2e6bd1dbcfa96f7772e26148024f8e08372eb0f2578b7a423e0977d38a | logcrypt 1.1.0 linux whl |
| e97b75897d3c60f52b48c3ac2627dbd3 | 984fda3f60393105ffa1a65c5d5d796fb79b199111fea0aa58dd0dfd53c58670 | logcrypt 1.1.0 win whl |
| 1e0152b6f28cdab4ab0d89f0331f4c14 | 2fe7212f145b72c65ea344c2b4f84e8978c15cf2c3954e7a2dcd9d2b96d273c1 | logfy 1.0.0 whl |
| f994cf7de9950f1c0066d97ee610d1b2 | dc619182973e08ab3dfc962dfbed1f24914b35c882d7a470b314fd151e85992b | filty 1.0 linux whl |
| 23a8178184c15edd3b7bf8b093acfa43 | dd44b97523a4617f473793d7ed9a2e7b1ef14297eb372cdf66853495a66b3be3 | filty 1.0 win whl |
| a9f36ffa024465f42e43f52bf57986b0 | 17997e9e0256d0f5d5d21a4852c37f16b338e4bb9c2bec09bdfd822b24aa76b4 | frint 0.1.2 any whl |
| a4e7201611aca0e318702cc156e3e21e | 6b27954d770c67199fb551aeb294847edd4ea6519e512ebeb1795b80e199b17d | skytext 1.0.0 linux whl |
| 58cededa00a4860c702dfd3c82dbdc85 | 94866b3f141aa118cff9edff281114c2fe3df58597ec27099c457a97c9ff602a | skytext 1.0.0 win whl |
| efc530361211ff2a7bb86ae373f3533e | 93739477cd379adef95126b22758c0e644282d2028dd297328ce856fa111dd06 | skytext 1.1.0 linux whl |
| b63f4f2197e22ded73418e404c904629 | 0a041f9a492d6c1f22342367b83c17ad5b2ca45d563fa76f7e51fed658bc61b7 | skytext 1.1.0 win whl |
| 10eff612a8ccb83530348728843c7c8b | 046678e23cda9cb331537a99578eb8ad733acffd84749ef23c0409ca8ab4de6a | gradient.pyd |
| ad8da167bad69fafdf76881a1ef6e586 | 79638c53a074b70b25beaa6772816790d6136da6db0c13fe68af60367ee7fb5a | gradient.so |
| 80b6047d11df7975ab19a4cb67704d53 | e4c14522c4bac2393809f49de456210779d49d99b843c9f5d31786da961701b6 | secure.pyd |
| 21f6f107528f3bf1c95b936327eb946c | 7e094042060e17239947fd514e76f37f8d140fd0d228233adb9714a279208dca | secure.so |
| da42b9237268cc9676a45b8a35ad42d7 | 14f2c5fff708407acf2749443dee0a08523a4a53f101503218a46b321ba7a31e | MeridianSpy (variant) |
| 2760923e9dfa835dd1f040666802f5fb | 3d3187b346249334b289cc83eeabe6bebe87fe1890978026d13949cc74893234 | MeridianSpy |
| 3f32e68730e6008ab009d85a95c9d2a8 | 94600d123b319926c021bb464799d2d99b4ac4d566bc0d86d94646b39ca1e156 | Test Payload |

---

### Network indicators

| Domain / URL / IP | Type |
| --- | --- |
| hxxps://api[.]mapbox[.]com/datasets/v1/mattallahsaed/cmismaye7000s1mp2v8fkn4lp/features/dm370543acmdopk296nahbtua?access_token=pk[.]eyJ1IjoibWF0dGFsbGFoc2FlZCIsImEiOiJjbWlzbWpncWkwNHRmM2ZzMWd1eTBmanQ4In0[.]VNFutzqzaSVfDiwQFr7_gQ | MeridianSpy C2 |
| 139[.]99[.]54[.]58 | Exfiltration C2 IP |
| hxxp://139[.]99[.]54[.]58:8088/api/v2/uswwwkuch2w2hwcg | Exfiltration C2 URL |
| hxxps://coda[.]io/apis/v1/docs/deXvpN0MPj/tables/grid-KJy93qPCNJ/rows | CoDawnloader C2 URL |
| hxxps://coda[.]io/apis/v1/docs/deXvpN0MPj/tables/grid-lW78IcOSED/rows | CoDawnloader C2 URL |
| hxxps://coda[.]io/apis/v1/docs/uNKrbCeNpv/tables/grid-4PQGo1sv7G/rows | CoDawnloader C2 URL |
| hxxps://coda[.]io/apis/v1/docs/uNKrbCeNpv/tables/grid-GT83o0FHu3/rows | CoDawnloader C2 URL |
