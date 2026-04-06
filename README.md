
# complex-xcipher

## Overview

1バイトのデータを複数バイトに分散させる暗号機能を提供します。

本ライブラリが提供する暗号機能は次の特徴を持ちます。

* データの断片がそれぞれランダムな位置に分散するため、単純に排他的論理和を掛けただけの暗号よりも解析が困難になる。
* ブロック型暗号かつデータ全体を要求するため、逐次的な暗号化・復号は行えない。
* 暗号化されたデータの中から指定位置にあるデータを復号して取り出すことができる。
* 暗号化されたデータの中の指定位置にあるデータを暗号化して書き換えることができる。
* 平文の長さは記録されないため、別途その情報を記録する必要がある。

```c
#include <stdio.h>
#include <stddef.h>
#include <complex-xcipher/complex-xcipher.h>

const char _PLAIN_DATA[] = "This is plain text.";

int main (){

  //初期化

  printf("Plain data: \"%s\"\n", _PLAIN_DATA);
  complex_xcipher_keyset keyset;
  complex_xcipher_keyset_auto_setup(0x1234567890, &keyset);

  //暗号化

  size_t encrypteddatasize;
  complex_xcipher_calc_encrypted_data_size(sizeof(_PLAIN_DATA), &encrypteddatasize);
  char encrypteddata[encrypteddatasize];
  complex_xcipher_encrypt(_PLAIN_DATA, sizeof(_PLAIN_DATA), &keyset, encrypteddata, encrypteddatasize);
  printf("Enctypted data: ");
  for (size_t i = 0; i < encrypteddatasize; i++){
    printf("%02x", encrypteddata[i]);
  }
  printf("\n");

  //復号

  char decrypteddata[sizeof(_PLAIN_DATA)];
  complex_xcipher_decrypt(0, sizeof(_PLAIN_DATA), encrypteddata, encrypteddatasize, &keyset, decrypteddata);
  printf("Decrypted data: \"%s\"\n", decrypteddata);

  return 0;
}
```

## Build & Test

```shell
make release test
```

### Docs

```shell
doxygen
```

## Donation

<a href="https://buymeacoffee.com/tikubonn" target="_blank"><img src="doc/img/qr-code.png" width="3000px" height="3000px" style="width:150px;height:auto;"></a>

もし本パッケージがお役立ちになりましたら、少額の寄付で支援することができます。<br>
寄付していただいたお金は書籍の購入費用や日々の支払いに使わせていただきます。
ただし、これは寄付の多寡によって継続的な開発やサポートを保証するものではありません。ご留意ください。

If you found this package useful, you can support it with a small donation.
Donations will be used to cover book purchases and daily expenses.
However, please note that this does not guarantee ongoing development or support based on the amount donated.

## License

© 2024-2026 tikubonn

complex-xcipher licensed under the [MIT License](./LICENSE).
