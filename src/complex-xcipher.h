
/**
 * @file
 * @brief １バイトのデータを複数バイトに分散させる暗号機能を提供します。
 */

#pragma once
#include <stddef.h>
#include <stdint.h>

/**
 * @brief 暗号鍵として使われる符号なし整数型です。
 */

typedef uint64_t complex_xcipher_key;

/**
 * complex_xcipher_key 型の最大値です。
 */

#define COMPLEX_XCIPHER_KEY_MAX UINT64_MAX

/**
 * @brief complex_xcipher_keyset_setup() 関数に指定する complex_xcipher_key 型配列の長さです。
 */

#define COMPLEX_XCIPHER_KEYS_LENGTH 11

/**
 * @brief 各種暗号関数が要求する暗号鍵の集合を表す構造体です。
 * @note この構造体は complex_xcipher_keyset_setup() 関数によって初期化されます。
 */

typedef struct complex_xcipher_keyset {
  complex_xcipher_key value_mask_seed;
  complex_xcipher_key index_mask;
  complex_xcipher_key bit_index_masks[8];
  complex_xcipher_key bit_ref_mask_seed;
} complex_xcipher_keyset;

/**
 * @brief complex_xcipher_keyset 構造体を初期化します。
 * @param keys 暗号鍵となる符号なし整数の配列です。
 * @param keyset 初期化する対象となる complex_xcipher_keyset 構造体です。
 * @note この関数は必ず成功します。
 */

extern void __stdcall complex_xcipher_keyset_setup (complex_xcipher_key keys[COMPLEX_XCIPHER_KEYS_LENGTH], complex_xcipher_keyset *keyset);

/**
 * @brief complex_xcipher_keyset 構造体を初期化します。本関数は complex_xcipher_keyset_setup 関数と異なり、1つの鍵から残りの鍵集合を作成します。
 * @param complex_xcipher_key keysource 鍵集合を作成するために用いられる complex_xcipher_key 整数です。
 * @param keyset 初期化する対象となる complex_xcipher_keyset 構造体です。
 * @note この関数は必ず成功します。
 */

extern void __stdcall complex_xcipher_keyset_auto_setup (complex_xcipher_key keysource, complex_xcipher_keyset *keyset);

/**
 * @brief 暗号化されたデータを保存する領域の最小限の大きさを計算します。
 * @param size 暗号化するデータの大きさです。
 * @param encrypteddatasizep 計算された領域の大きさを保存するための size_t 型のポインタです。
 * @return 成功ならば 0 失敗ならば 1 を返します。
 * @note size の値が 0 ならば、この関数は必ず成功し encrypteddatasizep には 0 が書き込まれます。
 * @warning 計算された領域の大きさが SIZE_MAX を超過してしまった場合、この関数は失敗します。
 */

extern int __stdcall complex_xcipher_calc_encrypted_data_size (size_t size, size_t *encrypteddatasizep);

/**
 * @brief データを暗号化します。暗号化されたデータは指定されたメモリ領域に書き込まれます。
 * @param data 暗号化するデータの先頭アドレスです。
 * @param datasize 暗号化するデータの大きさです。
 * @param keyset complex_xcipher_keyset_setup() 関数で初期化された complex_xcipher_keyset 構造体へのポインタです。
 * @param encrypteddata 暗号化されたデータが書き込まれるメモリ領域の先頭アドレスです。
 * @param encrypteddatasize complex_xcipher_calc_encrypted_data_size() 関数で計算された、暗号化されたデータが書き込まれるメモリ領域の大きさです。
 * @return 成功ならば 0 失敗ならば 1 を返します。
 * @warning datasize の値が encrypteddatasize よりも大きい場合、この関数は失敗します。
 * @warning data, encrypteddata が指す領域がそれぞれ重なっていた場合の動作は未定義です。
 */

extern int __stdcall complex_xcipher_encrypt (const void *data, size_t datasize, const complex_xcipher_keyset *keyset, void *encrypteddata, size_t encrypteddatasize);

/**
 * @brief データを暗号化します。暗号化されたデータは指定されたメモリ領域の、指定された位置に書き込まれます。
 * @param position データが書き込まれる位置です。これは平文を基準にした整数を指定します。
 * @param data 暗号化するデータの先頭アドレスです。
 * @param datasize 暗号化するデータの大きさです。
 * @param keyset complex_xcipher_keyset_setup() 関数で初期化された complex_xcipher_keyset 構造体へのポインタです。
 * @param encrypteddata 暗号化されたデータが書き込まれるメモリ領域の先頭アドレスです。
 * @param encrypteddatasize complex_xcipher_calc_encrypted_data_size() 関数で計算された、暗号化されたデータが書き込まれるメモリ領域の大きさです。
 * @return 成功ならば 0 失敗ならば 1 を返します。
 * @warning position, datasize の合計値が encrypteddatasize よりも大きい場合、この関数は失敗します。
 * @warning data, encrypteddata が指す領域がそれぞれ重なっていた場合の動作は未定義です。
 * @note この関数は既に暗号化されたデータを部分的に書き換えたい場合に使用することができます。
 */

extern int __stdcall complex_xcipher_encrypt_into (size_t position, const void *data, size_t datasize, const complex_xcipher_keyset *keyset, void *encrypteddata, size_t encrypteddatasize);

/**
 * @brief データを復号します。復号されたデータは指定されたメモリ領域に書き込まれます。
 * @param position 復号するデータの位置です。これは平文を基準にした整数を指定します。
 * @param size 復号するデータの大きさです。
 * @param data 暗号化されたデータの先頭アドレスです。
 * @param datasize complex_xcipher_calc_encrypted_data_size() 関数で計算された、暗号化されたデータの大きさです。
 * @param keyset complex_xcipher_keyset_setup() 関数で初期化された complex_xcipher_keyset 構造体へのポインタです。
 * @param decrypteddata 復号されたデータが書き込まれるメモリ領域の大きさ先頭アドレスです。
 * @return 成功ならば 0 失敗ならば 1 を返します。
 * @warning position, size の合計値が datasize よりも大きい場合、この関数は失敗します。
 * @warning data, decrypteddata が指す領域がそれぞれ重なっていた場合の動作は未定義です。
 * @note この関数は暗号化されたデータから部分的に読み込みたい場合にも使用することができます。
 */

extern int __stdcall complex_xcipher_decrypt (size_t position, size_t size, const void *data, size_t datasize, const complex_xcipher_keyset *keyset, void *decrypteddata);
