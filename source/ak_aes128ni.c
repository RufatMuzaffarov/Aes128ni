#include <stdio.h>
#include <string.h>
#include <wmmintrin.h>
#include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Псевдоним типа, который используется для определения размера области памяти,
           где хранятся раундовые ключи.                                                           */
/* ----------------------------------------------------------------------------------------------- */

typedef __m128i ak_aes_expanded_keys[20];

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция, освобождающая память, занимаемую развернутыми ключами.                         */
/* ----------------------------------------------------------------------------------------------- */

static int ak_aes_delete_keys( ak_skey skey )
{
 int error = ak_error_ok;

/* выполняем стандартные проверки */
 if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                __func__ , "using a null pointer to secret key" );
 if( skey->data != NULL ) {
  /* теперь очистка и освобождение памяти */
   if(( error = ak_ptr_wipe( skey->data, sizeof( ak_aes_expanded_keys ),
                                                            &skey->generator )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect wiping an internal data" );
     memset( skey->data, 0, sizeof( ak_aes_expanded_keys ));
   }
   free( skey->data );
   skey->data = NULL;
 }
return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Макрос, генерирующий раундовые ключи, в зависимости от номера раунда.
    \details При генерации раундовых ключей был использован набор инструкций процессора Intel:
                - _mm_aeskeygenassist_si128 -- Генерирует ключи раундов для шифрования
                                              на основе предыдущего ключа и значения RCON
                - _mm_xor_si128 -- Вычисляет битовую операцию Xor
                - _mm_slli_si128 -- Сдвигает key влево на 4 байта                                  */
/* ----------------------------------------------------------------------------------------------- */

#define AES128_KEYROUND(i, rcon) \
    key = ctx[i - 1]; \
    gen = _mm_aeskeygenassist_si128(key, rcon); \
    gen = _mm_shuffle_epi32(gen, 255); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4)); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4)); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4)); \
    ctx[i] = _mm_xor_si128(key, gen)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция, релизующая развертку ключей для алгоритма Aes для длины ключа = 128 бит
    \details При реализации развертки ключа был использован набор инструкций процессора Intel:
                - _mm_loadu_si128 -- Загружает 128-битные целочисленные данные из памяти
                - _mm_aesimc_si128 -- Конвертирует полученные ключи в форму, пригодную для
                                      дешифрования(Выполняет преобразование InvMixColumns)         */
/* ----------------------------------------------------------------------------------------------- */

static int ak_aes128_schedule_keys(ak_skey skey)
{
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                "using a null pointer to secret key" );
        if( skey->key_size != 16 ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                  "unsupported length of secret key" );
        /* проверяем целостность ключа */
        if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                    __func__ , "using key with wrong integrity code" );
        /* удаляем былое */
        if( skey->data != NULL ) ak_aes_delete_keys( skey );

        /* далее, по-возможности, выделяем выравненную память */
        if(( skey->data = ak_aligned_malloc( sizeof( ak_aes_expanded_keys ))) == NULL )
            return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                                 "wrong allocation of internal data" );
    __m128i * ctx = (__m128i *) skey->data;
    __m128i key, gen;
    ctx[0] = _mm_loadu_si128((__m128i *)skey->key);
    AES128_KEYROUND( 1, 0x01);
    AES128_KEYROUND( 2, 0x02);
    AES128_KEYROUND( 3, 0x04);
    AES128_KEYROUND( 4, 0x08);
    AES128_KEYROUND( 5, 0x10);
    AES128_KEYROUND( 6, 0x20);
    AES128_KEYROUND( 7, 0x40);
    AES128_KEYROUND( 8, 0x80);
    AES128_KEYROUND( 9, 0x1b);
    AES128_KEYROUND(10, 0x36);
    ctx[11] = _mm_aesimc_si128(ctx[9]);
    ctx[12] = _mm_aesimc_si128(ctx[8]);
    ctx[13] = _mm_aesimc_si128(ctx[7]);
    ctx[14] = _mm_aesimc_si128(ctx[6]);
    ctx[15] = _mm_aesimc_si128(ctx[5]);
    ctx[16] = _mm_aesimc_si128(ctx[4]);
    ctx[17] = _mm_aesimc_si128(ctx[3]);
    ctx[18] = _mm_aesimc_si128(ctx[2]);
    ctx[19] = _mm_aesimc_si128(ctx[1]);
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция релизует алгоритм зашифрования одного блока информации шифром AES-128.
    \details При реализации функции зашифрования был использован набор инструкций процессора Intel:
                - _mm_aesenc_si128 -- Выполняет один раунд шифрования, используя раундовый ключ
                - _mm_storeu_si128 -- Сохраняет 128-битные целочисленные данные в out              */
/* ----------------------------------------------------------------------------------------------- */

static void ak_aes128_encrypt(ak_skey skey, ak_pointer in, ak_pointer out)
{
    __m128i * ctx  = (__m128i *) skey->data;
    __m128i m = _mm_loadu_si128(in);
    m =        _mm_xor_si128(m, ctx[ 0]);
    m =     _mm_aesenc_si128(m, ctx[ 1]);
    m =     _mm_aesenc_si128(m, ctx[ 2]);
    m =     _mm_aesenc_si128(m, ctx[ 3]);
    m =     _mm_aesenc_si128(m, ctx[ 4]);
    m =     _mm_aesenc_si128(m, ctx[ 5]);
    m =     _mm_aesenc_si128(m, ctx[ 6]);
    m =     _mm_aesenc_si128(m, ctx[ 7]);
    m =     _mm_aesenc_si128(m, ctx[ 8]);
    m =     _mm_aesenc_si128(m, ctx[ 9]);
    m = _mm_aesenclast_si128(m, ctx[10]);
    _mm_storeu_si128(out, m);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция релизует алгоритм расшифрования одного блока информации шифром AES-128.
    \details При реализации функции расшифрования был использован набор инструкций процессора Intel:
                - _mm_aesdec_si128 -- Выполняет один раунд расшифрования, используя раундовый ключ */
/* ----------------------------------------------------------------------------------------------- */

static void ak_aes128_decrypt(ak_skey skey, ak_pointer in, ak_pointer out)
{
    __m128i * ctx  = (__m128i *) skey->data;
    __m128i m = _mm_loadu_si128(in);
    m =        _mm_xor_si128(m, ctx[10]);
    m =     _mm_aesdec_si128(m, ctx[11]);
    m =     _mm_aesdec_si128(m, ctx[12]);
    m =     _mm_aesdec_si128(m, ctx[13]);
    m =     _mm_aesdec_si128(m, ctx[14]);
    m =     _mm_aesdec_si128(m, ctx[15]);
    m =     _mm_aesdec_si128(m, ctx[16]);
    m =     _mm_aesdec_si128(m, ctx[17]);
    m =     _mm_aesdec_si128(m, ctx[18]);
    m =     _mm_aesdec_si128(m, ctx[19]);
    m = _mm_aesdeclast_si128(m, ctx[ 0]);
    _mm_storeu_si128(out, m);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Cпециальная функция маскирования, которая ничего не делает. Всегда возвращает OK.       */
/* ----------------------------------------------------------------------------------------------- */

int ak_skey_set_special_aes_mask(ak_skey skey){
    if((( skey->flags)&ak_key_flag_set_mask ) == 0 ) {
        skey->flags |= ak_key_flag_set_mask;
    }
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Cпециальная функция демаскирования, которая ничего не делает. Всегда возвращает OK.     */
/* ----------------------------------------------------------------------------------------------- */


int ak_skey_set_special_aes_unmask(ak_skey skey){
    if( (( skey->flags)&ak_key_flag_set_mask ) == 0 ) {
        return ak_error_ok;
    }
    skey->flags ^= ak_key_flag_set_mask;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция инициализации struct bckey для AES-128                                          */
/* ----------------------------------------------------------------------------------------------- */

int ak_bckey_create_aes( ak_bckey bkey )
{
  int error = ak_error_ok, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );

  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to block cipher key context" );
  if(( oc < 0 ) || ( oc > 1 )) return ak_error_message( ak_error_wrong_option, __func__,
                                                "wrong value for \"openssl_compability\" option" );

 /* создаем ключ алгоритма шифрования и определяем его методы */
  if(( error = ak_bckey_create( bkey, 16, 16 )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );

 /* ресурс ключа устанавливается в момент присвоения ключа */

 /* устанавливаем методы */
  bkey->schedule_keys = ak_aes128_schedule_keys;
  bkey->delete_keys = ak_aes_delete_keys;
  bkey->encrypt = ak_aes128_encrypt;
  bkey->decrypt = ak_aes128_decrypt;

  // установим свои специальные функции маскирования и демаскирования
  bkey->key.set_mask = ak_skey_set_special_aes_mask;
  bkey->key.unmask = ak_skey_set_special_aes_unmask;
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция тестирования AES-128 с данными (FIPS 197)                                                 */
/* ----------------------------------------------------------------------------------------------- */

void ak_aes128ni_tests()
{
    ak_uint8 key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    ak_uint8 pl_t[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    ak_uint8 out_of_enc[16];

    ak_uint8 enc_t[16] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
    };

    ak_uint8 out_of_dec[16];

    struct bckey test;
    ak_bckey_create_aes(&test);
    ak_bckey_set_key(&test, key, 16);

    ak_bckey_encrypt_ecb(&test, pl_t, out_of_enc, 16);
    if (memcmp(out_of_enc, enc_t, sizeof(out_of_enc)))
        printf("FAIL: encryption\n");
    else
        printf("PASS: encryption\n");

    ak_bckey_decrypt_ecb(&test, enc_t, out_of_dec, 16);
    if (memcmp(out_of_dec, pl_t, sizeof(out_of_dec)))
        printf("FAIL: decryption\n");
    else
        printf("PASS: decryption\n");
}
