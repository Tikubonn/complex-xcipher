
#include <stddef.h>
#include <stdint.h>
#include <complex-xcipher/complex-xcipher.h>
#include "test.h"

static void testcase (){
  {
    size_t encrypteddatasize;
    TEST(complex_xcipher_calc_encrypted_data_size(0, &encrypteddatasize) == 0);
    TEST(encrypteddatasize == 0, "%zu", encrypteddatasize);
  }
  {
    size_t encrypteddatasize;
    TEST(complex_xcipher_calc_encrypted_data_size(1, &encrypteddatasize) == 0);
    TEST(encrypteddatasize == 2, "%zu", encrypteddatasize);
  }
  {
    size_t encrypteddatasize;
    TEST(complex_xcipher_calc_encrypted_data_size(2, &encrypteddatasize) == 0);
    TEST(encrypteddatasize == 2, "%zu", encrypteddatasize);
  }
  {
    size_t encrypteddatasize;
    TEST(complex_xcipher_calc_encrypted_data_size(3, &encrypteddatasize) == 0);
    TEST(encrypteddatasize == 4, "%zu", encrypteddatasize);
  }
  {
    size_t encrypteddatasize;
    TEST(complex_xcipher_calc_encrypted_data_size(100, &encrypteddatasize) == 0);
    TEST(encrypteddatasize == 128, "%zu", encrypteddatasize);
  }
  {
    size_t encrypteddatasize;
    TEST(complex_xcipher_calc_encrypted_data_size(200, &encrypteddatasize) == 0);
    TEST(encrypteddatasize == 256, "%zu", encrypteddatasize);
  }
  {
    size_t encrypteddatasize;
    TEST(complex_xcipher_calc_encrypted_data_size(300, &encrypteddatasize) == 0);
    TEST(encrypteddatasize == 512, "%zu", encrypteddatasize);
  }
  {
    size_t encrypteddatasize;
    TEST(complex_xcipher_calc_encrypted_data_size(SIZE_MAX >> 1, &encrypteddatasize) == 0);
    TEST(encrypteddatasize < SIZE_MAX);
  }
  {
    size_t encrypteddatasize;
    TEST(complex_xcipher_calc_encrypted_data_size(SIZE_MAX, &encrypteddatasize) != 0);
  }
}

void test_complex_xcipher_calc_encrypted_data_size (){
  testcase();
}
