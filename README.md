ECDSA署名実装
====

TEPLA(University of Tsukuba
Elliptic Curve and Pairing Library)を利用したECDSA署名の実装

## 詳細
TEPLAで128bitセキュリティのECDSA署名を実装したため公開する。
あくまで、研究の評価を行うために作成したためClass等のインターフェースはまだまだ不十分であると思われるため要望があれば順次対応するつもりである。  
また、バグ等の指摘も歓迎します。  
簡単な実装の解説PDFも添付しています。(*[ecdsa_presen.pdf](ecdsa_presen.pdf)*)  
また、適当な平文に署名をつけ、検証を行う実装速度の測定プログラムも作成しています。

## 環境
* gcc
* TEPLA1.0  
  DockerのTEPLAイメージファイルを作成したためこれを利用すると環境導入が容易になる。
<https://registry.hub.docker.com/u/natsu/tepla/>


## 使い方

### サンプルコードの実行
```sh
$ make
$ ./main
```

サンプルコード
使い方はサンプルコードを参照されたし。
```cpp
#undef NDEBUG
#include <iostream>
#include <assert.h>

#include "ecdsa.h"

int main()
{
  Sig::init();
  Sig hoge;
  string m = "hogehoge";
  bool r1, r2;

  hoge.sign(m);
  r1 = hoge.vrfy(m);
  r2 = hoge.vrfy("hogehogf");
  assert( true  == r1 );
  assert( false == r2 );

  Sig::fin();
  return 0;
}

```

### 速度測定方法
```sh
$ cd speed
$ make
$ ./speed_check
```
平文の個数は*speed_check.cpp*の*num*で指定、平文の文字列は*str_len*を変更すると良い。

## ライセンス

This software is released under the MIT License, see [LICENSE.txt](LICENCE.txt)

## 参考文献

* [TEPLA](http://www.cipher.risk.tsukuba.ac.jp/tepla/)
* [ECDSA 評価報告書](http://www.cryptrec.go.jp/estimation/rep_ID0003.pdf)
