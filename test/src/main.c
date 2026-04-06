
#include "test-complex-xcipher-calc-encrypted-data-size.h"
#include "test-complex-xcipher-encrypt.h"
#include "test-complex-xcipher-encrypt-into.h"
#include "test-complex-xcipher-decrypt.h"

int main (){
  test_complex_xcipher_calc_encrypted_data_size();
  test_complex_xcipher_encrypt();
  test_complex_xcipher_encrypt_into();
  test_complex_xcipher_decrypt();
  return 0;
}
