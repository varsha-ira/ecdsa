#undef NDEBUG
#include <iostream>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <cstdlib>

#include "../ecdsa.h"
 
double getrusageSec(){
  struct rusage t;
  struct timeval s;
  getrusage(RUSAGE_SELF, &t);
  s = t.ru_utime;
  return s.tv_sec + (double)s.tv_usec*1e-6;
}

/* Maximum value of resident set size on RAM */
long getrusageSize(){
  struct rusage t;
  struct timeval s;
  getrusage(RUSAGE_SELF, &t);
  // cout << "ru_maxrss: " << t.ru_maxrss << " K bytes";   /* maximum resident set size */

  return t.ru_maxrss;
}

// function that generates random string of len characters
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
  // initilize the seed of random number by current time
  srand((unsigned)time(NULL));
  const unsigned int num = 100;
  const char str_len = 100;
  string text_data[num];
  double st[5], et[5];

  // generate num strings of len characters
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
  st[0] = st[1] = getrusageSec();

  Sig::init();
  Sig* sigs = new Sig[num];
  bool r1, r2;

  et[1] = st[2] = getrusageSec();
  for (int i=0; i<num; i++) {
    sigs[i].sign(text_data[i]);
  }

  et[2] = st[3] = getrusageSec();

  for (int i=0; i<num; i++) {
    // r1 = false; r2 = false;
    r1 = sigs[i].vrfy(text_data[i]);
    // assert( true  == r1 );
  }

  et[3] = st[4] = getrusageSec();

  cout << "\nsignature: \n";
  cout << "   value: \n";
  gmp_printf("     r = %Zx", sigs[0].get_sig("r"));
  gmp_printf("     s = %Zx\n", sigs[0].get_sig("s"));
  gmp_printf("     r = %Zx", sigs[1].get_sig("r"));
  gmp_printf("     s = %Zx\n", sigs[1].get_sig("s"));
  cout << "         ... (" << num << ")\n";

  char sr[128], ss[128];
  mpz_get_str(sr, 16, *sigs[0].get_sig("r"));
  mpz_get_str(ss, 16, *sigs[0].get_sig("s"));
  cout << "   size:  " << ((strlen(sr)+strlen(ss))*sizeof(char)*num) << " bytes" << endl;

  // delete
  delete [] sigs;
  Sig::fin();

  et[4] = et[0] = getrusageSec();

  cout << "init   time = " << (et[1] - st[1]) << " sec" << endl;
  cout << "sign   time = " << (et[2] - st[2]) << " sec" << endl;
  cout << "verify time = " << (et[3] - st[3]) << " sec" << endl;
  cout << "final  time = " << (et[4] - st[4]) << " sec" << endl;
  cout << "entire time = " << (et[0] - st[0]) << " sec" << endl;
  cout << "memory size:  " << getrusageSize() << " bytes " << endl;

  
  return 0;
}
