
#include <stddef.h>
#include <stdint.h>
#include "complex-xcipher.h"

static inline uint64_t xorlshift64 (uint64_t n){
  n ^= n << 13;
  n ^= n >> 7;
  n ^= n << 17;
  return n;
}

static inline uint8_t complex_xcipher_keyset_calc_value (uint8_t value, size_t index, const complex_xcipher_keyset *keyset){
  return value ^ xorlshift64(index + keyset->value_mask_seed);
}

static inline size_t complex_xcipher_keyset_calc_index (size_t index, size_t size, const complex_xcipher_keyset *keyset){
  return (index ^ keyset->index_mask) & (size -1);
}

static inline size_t complex_xcipher_keyset_calc_bit_index (size_t bitindex, size_t baseindex, size_t size, const complex_xcipher_keyset *keyset){
  return ((bitindex + baseindex) ^ keyset->bit_index_masks[bitindex]) & (size -1);
}

static inline size_t complex_xcipher_keyset_calc_bit_ref (size_t bitindex, size_t index, const complex_xcipher_keyset *keyset){
  return (bitindex ^ xorlshift64(index + keyset->bit_ref_mask_seed)) & 0x07;
}

void __stdcall complex_xcipher_keyset_setup (complex_xcipher_key keys[COMPLEX_XCIPHER_KEYS_LENGTH], complex_xcipher_keyset *keyset){
  keyset->value_mask_seed = keys[0];
  keyset->index_mask = keys[1];
  for (size_t i = 0; i < 8; i++){
    keyset->bit_index_masks[i] = keys[i + 2];
  }
  keyset->bit_ref_mask_seed = keys[10];
}

void __stdcall complex_xcipher_keyset_auto_setup (complex_xcipher_key keysource, complex_xcipher_keyset *keyset){
  complex_xcipher_key keys[COMPLEX_XCIPHER_KEYS_LENGTH];
  complex_xcipher_key k = keysource;
  for (size_t i = 0; i < COMPLEX_XCIPHER_KEYS_LENGTH; i++){
    k = xorlshift64(k);
    keys[i] = k;
  }
  complex_xcipher_keyset_setup(keys, keyset);
}

int __stdcall complex_xcipher_calc_encrypted_data_size (size_t size, size_t *encrypteddatasizep){
  if (0 < size){
    for (size_t bi = 1; bi < sizeof(size_t) * 8; bi++){
      size_t bs = 1 << bi;
      if (bs <= SIZE_MAX){
        if (size <= bs){
          *encrypteddatasizep = bs;
          return 0;
        }
      }
      else {
        break;
      }
    }
    return 1;
  }
  else {
    *encrypteddatasizep = 0;
    return 0;
  }
}

int __stdcall complex_xcipher_encrypt (const void *data, size_t datasize, const complex_xcipher_keyset *keyset, void *encrypteddata, size_t encrypteddatasize){
  if (datasize <= encrypteddatasize){
    for (size_t i = 0; i < datasize; i++){
      uint8_t value = complex_xcipher_keyset_calc_value(((uint8_t*)data)[i], i, keyset);
      // uint8_t value = ((uint8_t*)data)[i];
      size_t index = complex_xcipher_keyset_calc_index(i, encrypteddatasize, keyset);
      for (size_t bi = 0; bi < 8; bi++){
        size_t bitindex = complex_xcipher_keyset_calc_bit_index(bi, index, encrypteddatasize, keyset);
        size_t bitref = complex_xcipher_keyset_calc_bit_ref(bi, i, keyset);
        uint8_t v = (value & (1 << bitref)) >> bitref;
        ((uint8_t*)encrypteddata)[bitindex] &= ~(1 << bi);
        ((uint8_t*)encrypteddata)[bitindex] |= v << bi;
      }
    }
    for (size_t i = datasize; i < encrypteddatasize; i++){
      uint8_t value = complex_xcipher_keyset_calc_value(0, i, keyset);
      // uint8_t value = 0;
      size_t index = complex_xcipher_keyset_calc_index(i, encrypteddatasize, keyset);
      for (size_t bi = 0; bi < 8; bi++){
        size_t bitindex = complex_xcipher_keyset_calc_bit_index(bi, index, encrypteddatasize, keyset);
        size_t bitref = complex_xcipher_keyset_calc_bit_ref(bi, i, keyset);
        uint8_t v = (value & (1 << bitref)) >> bitref;
        ((uint8_t*)encrypteddata)[bitindex] &= ~(1 << bi);
        ((uint8_t*)encrypteddata)[bitindex] |= v << bi;
      }
    }
    return 0;
  }
  else {
    return 1;
  }
}

int __stdcall complex_xcipher_encrypt_into (size_t position, const void *data, size_t datasize, const complex_xcipher_keyset *keyset, void *encrypteddata, size_t encrypteddatasize){
  if (position + datasize <= encrypteddatasize){
    for (size_t i = 0; i < datasize; i++){
      size_t p = position + i;
      uint8_t value = complex_xcipher_keyset_calc_value(((uint8_t*)data)[i], p, keyset);
      // uint8_t value = ((uint8_t*)data)[i];
      size_t index = complex_xcipher_keyset_calc_index(p, encrypteddatasize, keyset);
      for (size_t bi = 0; bi < 8; bi++){
        size_t bitindex = complex_xcipher_keyset_calc_bit_index(bi, index, encrypteddatasize, keyset);
        size_t bitref = complex_xcipher_keyset_calc_bit_ref(bi, p, keyset);
        uint8_t v = (value & (1 << bitref)) >> bitref;
        ((uint8_t*)encrypteddata)[bitindex] &= ~(1 << bi);
        ((uint8_t*)encrypteddata)[bitindex] |= v << bi;
      }
    }
    return 0;
  }
  else {
    return 1;
  }
}

int __stdcall complex_xcipher_decrypt (size_t position, size_t size, const void *data, size_t datasize, const complex_xcipher_keyset *keyset, void *decrypteddata){
  if (position + size <= datasize){
    for (size_t i = 0; i < size; i++){
      size_t p = position + i;
      size_t index = complex_xcipher_keyset_calc_index(p, datasize, keyset);
      uint8_t v = 0;
      for (size_t bi = 0; bi < 8; bi++){
        size_t bitindex = complex_xcipher_keyset_calc_bit_index(bi, index, datasize, keyset);
        size_t bitref = complex_xcipher_keyset_calc_bit_ref(bi, p, keyset);
        uint8_t n = (((uint8_t*)data)[bitindex] & (1 << bi)) >> bi;
        v |= n << bitref;
      }
      uint8_t value = complex_xcipher_keyset_calc_value(v, p, keyset);
      // uint8_t value = v;
      ((uint8_t*)decrypteddata)[i] = value;
    }
    return 0;
  }
  else {
    return 1;
  }
}

void __stdcall complex_xcipher_clear (void *data, size_t datasize, uint64_t seed){
  uint64_t rand = seed;
  for (size_t i = 0; i < datasize; i++){
    rand = xorlshift64(rand);
    ((uint8_t*)data)[i] = rand;
  }
}
