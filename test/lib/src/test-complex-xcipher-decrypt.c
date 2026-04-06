
#include <stddef.h>
#include <stdint.h>
#include <complex-xcipher/complex-xcipher.h>
#include "test.h"

static void testcase_error (){
  uint8_t plaindata[100] = {0};
  complex_xcipher_key keys[11] = {0};
  complex_xcipher_keyset keyset;
  complex_xcipher_keyset_setup(keys, &keyset);
  size_t encrypteddatasize;
  TEST(complex_xcipher_calc_encrypted_data_size(sizeof(plaindata), &encrypteddatasize) == 0);
  TEST(encrypteddatasize == 128);
  uint8_t encrypteddata[encrypteddatasize];
  TEST(complex_xcipher_encrypt(plaindata, sizeof(plaindata), &keyset, encrypteddata, encrypteddatasize) == 0);
  {
    uint8_t decrypteddata[sizeof(plaindata)];
    TEST(complex_xcipher_decrypt(0, sizeof(decrypteddata), encrypteddata, encrypteddatasize, &keyset, decrypteddata) == 0);
  }
  {
    uint8_t decrypteddata[sizeof(plaindata)];
    TEST(complex_xcipher_decrypt(0, 0, encrypteddata, encrypteddatasize, &keyset, decrypteddata) == 0);
  }
  {
    uint8_t decrypteddata[sizeof(plaindata)];
    TEST(complex_xcipher_decrypt(encrypteddatasize, 0, encrypteddata, encrypteddatasize, &keyset, decrypteddata) == 0);
  }
  {
    uint8_t decrypteddata[sizeof(plaindata)];
    TEST(complex_xcipher_decrypt(encrypteddatasize, 1, encrypteddata, encrypteddatasize, &keyset, decrypteddata) != 0);
  }
}

static void testcase (){
  uint8_t plaindata[100];
  for (size_t i = 0; i < sizeof(plaindata); i++){
    plaindata[i] = i;
  }
  complex_xcipher_key keys[11] = {0};
  complex_xcipher_keyset keyset;
  complex_xcipher_keyset_setup(keys, &keyset);
  size_t encrypteddatasize;
  TEST(complex_xcipher_calc_encrypted_data_size(sizeof(plaindata), &encrypteddatasize) == 0);
  TEST(encrypteddatasize == 128, "%zu", encrypteddatasize);
  uint8_t encrypteddata[encrypteddatasize];
  TEST(complex_xcipher_encrypt(plaindata, sizeof(plaindata), &keyset, encrypteddata, encrypteddatasize) == 0);
  {
    uint8_t decrypteddata[sizeof(plaindata)];
    TEST(complex_xcipher_decrypt(0, sizeof(decrypteddata), encrypteddata, encrypteddatasize, &keyset, decrypteddata) == 0);
    for (size_t i = 0; i < sizeof(decrypteddata); i++){
      TEST(decrypteddata[i] == plaindata[i], "i=%zu, %d, %d", i, decrypteddata[i], plaindata[i]);
    }
  }
  {
    uint8_t decrypteddata[50];
    TEST(complex_xcipher_decrypt(0, 50, encrypteddata, encrypteddatasize, &keyset, decrypteddata) == 0);
    for (size_t i = 0; i < 50; i++){
      TEST(decrypteddata[i] == plaindata[i], "i=%zu, %d, %d", i, decrypteddata[i], plaindata[i]);
    }
  }
  {
    uint8_t decrypteddata[50];
    TEST(complex_xcipher_decrypt(50, 50, encrypteddata, encrypteddatasize, &keyset, decrypteddata) == 0);
    for (size_t i = 0; i < 50; i++){
      TEST(decrypteddata[i] == plaindata[i + 50], "i=%zu, %d, %d", i, decrypteddata[i], plaindata[i + 50]);
    }
  }
}

void test_complex_xcipher_decrypt (){
  testcase_error();
  testcase();
}
