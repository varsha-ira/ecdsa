#include <iostream>
#include <iomanip>
using namespace std;

#include <string>
#include <vector>
#include <gmp.h>
// #include <gmpxx.h>
#include <openssl/sha.h>
#include <sstream>

#ifdef __cplusplus
  extern "C" {
    #include <tepla/ec.h>
  }
#endif

// add my comments here....
void point_print( const string , const EC_POINT );
void element_print( const string , const Element );
string get_hex_string( unsigned char*, size_t );

void point_print(const string s, const EC_POINT x)
{
  int size = point_get_str_length(x);
  char *str = new char[size];

  point_get_str(str, x);
  cout << s << str << endl;

  delete [] str;
}

void element_print(const string s, const Element x)
{
  int size = element_get_str_length(x);
  char *str = new char[size];

  element_get_str(str, x);
  cout << s << str << endl;

  delete [] str;
}

// transform array data of byte sequences into string data of hexadecimal
string get_hex_string( unsigned char *data, size_t n )
{
  stringstream ss;

	for ( size_t i = 0; i < n; i++ )
	{
    // cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    // transform 2 byte data into string of hexadecimal and connect
    // (if it casted data into int, don't run)
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
	}

  return ss.str();
}

class Sig
{
  public:
    Sig();
    ~Sig();
    mpz_t* get_sig(char*);  // char c = "r" or "s"
    void key_gen();
    void sign( const string );
    bool vrfy( const string );
    static void init()
    {
      mpz_init(tmp);
      mpz_init(n);

      curve_init(ec, "ec_bn254_fp");
      mpz_set(n, *curve_get_order(ec));
      // gmp_printf ("curve order:  %Zx\n", n);
      point_init(G, ec);

      gen_G();
      // point_print("", G);

      field_init(f, "bn254_fp");
      
      // init of random num
      gmp_randinit_default(r_state);
      gmp_randseed_ui(r_state, (unsigned long)time(NULL));
    }

    static void fin()
    {
      field_clear(f);
      point_clear(G);
      // curve_clear(ec); // segmentation fault 11 ??
      mpz_clear(tmp);
      mpz_clear(n);
      gmp_randclear(r_state);
    }


  private:
    static EC_GROUP ec; // elliptic curve
    static EC_POINT G;  // generator
    static Field f ;
    static mpz_t tmp;
    static mpz_t n;   // order of curve
    static gmp_randstate_t r_state;  // radomn state
    EC_POINT Q; // public key
    mpz_t d;  // secret key
    mpz_t r,s;  // Signature: S = (r,s)

    static void gen_G();
    void set_mpz_from_element( mpz_t , Element );

};

EC_GROUP Sig::ec;
EC_POINT Sig::G;
Field Sig::f;
mpz_t Sig::tmp;
mpz_t Sig::n;
gmp_randstate_t Sig::r_state;

Sig::Sig()
{
  point_init(Q , ec);
  mpz_init(r);
  mpz_init(s);
  mpz_init(d);

  key_gen();
}

Sig::~Sig()
{
  point_clear(Q);
  mpz_clear(r);
  mpz_clear(s);
  mpz_clear(d);
}

mpz_t* Sig::get_sig(char* c)
{
  if (c == "r") {
    return &this->r;
  } else if (c == "s") {
      return &this->s;
  } else {
    cout << "get_sig: argument is 'r' or 's'\n";
    return 0;
  }

}

// Key Generation
void Sig::key_gen()
{
// *** generation of secret key 'd' (random value) ***
  // Generate a uniform random integer in the range 0 to n-1, inclusive.
  mpz_urandomm(d, this->r_state, this->n);
  // gmp_printf("scret key d: %Zx\n", d);

// *** generation of public key 'Q' ***
  point_mul(Q, d, G);  // Q ← G^d
}

// Signing

// ***** Hash info *****
// Hash sample http://d.hatena.ne.jp/Guernsey/20100622/1277185273
// Hash command: $ echo -n "The quick brown fox jumps over the lazy dog" | openssl dgst -sha256
// *********************

void Sig::sign( const string M )
{
// *** initialization ***
	unsigned char hash[SHA256_DIGEST_LENGTH];

  mpz_t m, k, t;
  mpz_init(m);
  mpz_init(k);
  mpz_init(t);

  EC_POINT P, T;
  point_init(P, ec);
  point_init(T, ec);


// *** generation of signature 'S = (r,s)' ***
  do {
    // Generate a uniform random integer in the range 0 to n-1, inclusive.
    mpz_urandomm(k, this->r_state, this->n);
    // gmp_printf("radom num k: %Zx\n", k);

    point_mul(P, k, G);  // P ← k*G
    // point_print("P: ", P);

    // translate into affine coordinate just in case(, but this handling may be not necessary becase output z-coordinate value was 1)
    point_make_affine(T, P);
    // element_print("x is ", T->x); element_print("y is ", T->y); element_print("z is ", T->z);
    set_mpz_from_element(this->r, T->x); 
    mpz_mod(this->r, this->r, this->n);   // r = x1 mod n


  // *** Hash Computation ***
    // *** m ← H(M) ***
    SHA256( (unsigned char *)M.c_str(), M.length(), hash );
    mpz_set_str(m, get_hex_string(hash, SHA256_DIGEST_LENGTH ).c_str(), 16);
    // gmp_printf("m: %Zx\n", m);
    
  // *** compute 's' ***
    // * s = k^(-1)*(m+d*r) mod n
    mpz_invert(k, k, this->n);  // k = k^-1
    mpz_mul(t, d, r);  // t = d*r
    mpz_add(t, m, t); // t = m+t = m+d*r
    mpz_mul(s, k, t); // s = t = k*t = k^(-1)*(m+d*r)
    mpz_mod(s, s, this->n);
    /*
    cout << "** Signature S = (r,s)\n";
    gmp_printf("r: %Zx\n", r);
    gmp_printf("s: %Zx\n\n", s);
    */

  } while ( mpz_sgn(r) == 0 or mpz_sgn(s) == 0 );
  // r == 0 or s == 0

// *** finalization ***
  mpz_clear(t);
  mpz_clear(k);
  mpz_clear(m);
  point_clear(P);
  point_clear(T);
}

// Verification
bool Sig::vrfy(const string M )
{
// *** initialization ***
	unsigned char hash[SHA256_DIGEST_LENGTH];
  bool rslt = false;

  mpz_t m, u1, u2, t;
  mpz_init(m);
  mpz_init(u1);
  mpz_init(u2);
  mpz_init(t);

  EC_POINT R, T1, T2;
  point_init(R, ec);
  point_init(T1, ec);
  point_init(T2, ec);

// *** Hash Computation ***
  // *** m ← H(M) ***
  SHA256( (unsigned char *)M.c_str(), M.length(), hash );
  mpz_set_str(m, get_hex_string(hash, SHA256_DIGEST_LENGTH ).c_str(), 16);
  // gmp_printf("m: %Zx\n", m);

// *** compute u1, u2 ***
  mpz_invert(t, this->s, this->n); // t = s^(-1)
  // u1 = m*s^(-1) mod n
  mpz_mul(u1, m, t);        // u1 = m*t = m*s^(-1)
  mpz_mod(u1, u1, this->n); // u1 = m*t = m*s^(-1) mod n
  // u2 = r*s^(-1) mod n
  mpz_mul(u2, this->r, t);  // u2 = r*t = r*s^(-1)
  mpz_mod(u2, u2, this->n); // u2 = r*t = r*s^(-1) mod n


// *** compute R = (xr, yr) ***
// *** R = (xr, yr) = u1*G - u2*Q

  point_mul(T1, u1, this->G);  // T1 ← u1*G
  point_mul(T2, u2, this->Q);  // T2 ← u2*Q
  // point_sub(R, T1, T2); // R = T1 - T2 = u1*G - u2*Q
  point_add(R, T1, T2); // R = T1 + T2 = u1*G + u2*Q

  set_mpz_from_element(t, R->x); 
  mpz_mod(t, t, this->n);

  if (mpz_cmp(t, this->r) == 0) {
    // if t eq r then valid
    rslt =  true;
  } else {
    // if (R = O) or (t not eq r) then invalid
    rslt = false;
  }


// *** finalization ***
  mpz_clear(m);
  mpz_clear(u1);
  mpz_clear(u2);
  mpz_clear(t);
  point_clear(R);
  point_clear(T1);
  point_clear(T2);

  return rslt;
}

void Sig::gen_G()
{
  // init
  mpz_set(tmp, ec->cofactor);
  // gmp_printf ("%s is an mpz %Zd\n", "cofactor", tmp);
  EC_POINT P;
  point_init(P, ec);

  do {
    point_random(P);
    point_mul(G, tmp, P);
    // cout << point_is_infinity(G) << endl;
  } while (point_is_infinity(G) != 0) ;   // exit not infinity
  /*
  point_print("G", G);
  point_mul(P, *curve_get_order(ec), G);
  point_print("G * order", P);
  */

  // clear
  point_clear(P);
}

void Sig::set_mpz_from_element(mpz_t tmp, Element x)
{
  int size = element_get_str_length(x);
  char *str = new char[size];

  element_get_str(str, x);

  mpz_set_str(tmp, str, 16);
  // gmp_printf ("%s is an mpz %Zx\n", "value of x", tmp);

  delete [] str;
}
