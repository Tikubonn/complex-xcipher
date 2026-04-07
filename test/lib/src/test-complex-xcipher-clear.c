
#include <stddef.h>
#include <stdint.h>
#include <complex-xcipher/complex-xcipher.h>
#include "test.h"

#define SAMPLE_TEXT "This is a secret data."

static void testcase (){
  uint8_t sampledata[] = SAMPLE_TEXT;
  complex_xcipher_clear(sampledata, sizeof(sampledata), 123);
  for (size_t i = 0; i < sizeof(sampledata); i++){
    TEST(sampledata[i] != SAMPLE_TEXT[i], "%u, %u", sampledata[i], SAMPLE_TEXT[i]);
  }
}

static void testcase_macro (){
  uint8_t sampledata[] = SAMPLE_TEXT;
  COMPLEX_XCIPHER_CLEAR(sampledata, sizeof(sampledata));
  for (size_t i = 0; i < sizeof(sampledata); i++){
    TEST(sampledata[i] != SAMPLE_TEXT[i], "%u, %u", sampledata[i], SAMPLE_TEXT[i]);
  }
}

void test_complex_xcipher_clear (){
  testcase();
  testcase_macro();
}
