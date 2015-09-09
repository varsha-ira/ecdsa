IMPLEMENTATION OF ECDSA SIGNATURE
====

I implement ECDSA signature by using TEPLA(University of Tsukuba Elliptic Curve and Pairing Library).

## Detail
I publish program source codes of ECDSA signature on 128 bit security.
I implemented this program to evaluate my proposed method in my research,
so I think it an imperfect implemantation about Class interfaces and so on.
If you had some requests, comments or bug reports, I will respond it as much as I can. 
And I attach a simple explanation PDF file of my implemantation in Japanese. (*[ecdsa_presen.pdf](ecdsa_presen.pdf)*)  
Also I implemented speed determination programs that signs some plaintexts and verifies signatures.

## Environment
* gcc
* TEPLA1.0  
  I create TEPLA image file of Docker, so you can easily install the environment if you used this. 
<https://registry.hub.docker.com/u/natsu/tepla/>


## Usage

### Execution of sample code
```sh
$ make
$ ./main
```

**Sample Code**  
Please, refer the following sample code and understand how to use this program.

```cpp
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

### Speed determination way
```sh
$ cd speed
$ make
$ ./speed_check
```
You can assign the number of plaintexts and the length of plaintexts, each value is *num* and *str_len* in *speed_check.cpp*.

## LICENCE

This software is released under the MIT License, see [LICENCE.txt](LICENCE.txt)

## Reference

* [TEPLA](http://www.cipher.risk.tsukuba.ac.jp/tepla/)
* [ECDSA 評価報告書](http://www.cryptrec.go.jp/estimation/rep_ID0003.pdf)
