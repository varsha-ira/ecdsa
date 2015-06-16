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

  // cout << "please input message: ";
  // cin >> m;
  hoge.sign(m);
  r1 = hoge.vrfy(m);
  r2 = hoge.vrfy("hogehogf");
  assert( true  == r1 );
  assert( false == r2 );

  Sig::fin();
  return 0;
}
