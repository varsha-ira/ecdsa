#undef NDEBUG
#include <iostream>
#include <string>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "../ecdsa.h"
 
double getrusageSec(){
  struct rusage t;
  struct timeval s;
  getrusage(RUSAGE_SELF, &t);
  s = t.ru_utime;
  return s.tv_sec + (double)s.tv_usec*1e-6;
}

// len 文字のランダムな文字列を作成する関数
string str_gen(char len)
{
  string str_data = "";
  string material = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

  for (int i=0; i<len; i++)
    str_data.append (1, material[rand()%(material.size()-1)]);

  return str_data;
}
int main()
{
  // 乱数のシードを現在の時刻で初期化
  srand((unsigned)time(NULL));
  const unsigned int num = 1000;
  const char str_len = 10;
  string text_data[num];

  // len文字のnum個の文字列を作成する
  for (int i=0; i<num; i++)
    text_data[i] = str_gen(str_len);

  /*
  for (int i=0; i<num; i++)
    cout << text_data[i] << endl;
  /**/

  cout << "+-------------------------+\n";
  cout << "text length = " << (int)str_len << endl;
  cout << "number of text = " << (int)num << endl;
  cout << "+-------------------------+\n";


  /* normal signature speed determination */

  cout << "********* Time of ECDSA ********* \n";
  double start = getrusageSec();

  Sig::init();
  Sig hoge[num];
  bool r1, r2;

  double sign_st = getrusageSec();
  for (int i=0; i<num; i++) {
    hoge[i].sign(text_data[i]);
  }
  double sign_et = getrusageSec();

  double vrfy_st = getrusageSec();
  for (int i=0; i<num; i++) {
    // r1 = false; r2 = false;
    r1 = hoge[i].vrfy(text_data[i]);
    // assert( true  == r1 );
  }

  double end = getrusageSec();
  cout << "sign time = " << (sign_et - sign_st) << " sec" << endl;
  cout << "verify time = " << (end - vrfy_st) << " sec" << endl;
  cout << "entire time = " << (end - start) << " sec" << endl;

  Sig::fin();
  
  return 0;
}
