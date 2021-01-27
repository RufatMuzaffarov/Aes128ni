# Aes128ni
Было реализовано встраивание реализации алгоритма блочного шифрования AES-128 с дополнительным набором инструкций процессоров Intel.

Для встраивания реализции алгоритма шифрования AES128ni в библиотеку было добавлено два файла : `source/ak_aes128ni.c` и `examples/test-aes128ni.c`

Добавлены следующие строки в коде файла `CMakeLists.txt`:

* source/ak_aes128ni.c          на строке 85
* set(CMAKE_C_FLAGS "-maes")    на строке 90
* aes128ni                      на строке 200        

Добавлено описание следующих функций в файл `libakrypt.h`:

* void ak_aes128ni_tests(void)                  на строке 182

* int ak_bckey_create_aes( ak_bckey bkey )      на строке 693
 
В файле `ak_aes128ni.c` находится реализация алгоритма; в ней определены следующие функции:

Функции зашифрования и расшифрования:

* static void ak_aes128_encrypt(ak_skey skey, ak_pointer in, ak_pointer out)
    
* static void ak_aes128_decrypt(ak_skey skey, ak_pointer in, ak_pointer out)
    
Функции для работы с ключами:

* static int ak_aes_delete_keys(ak_skey skey)

* static int ak_aes128_schedule_keys(ak_skey skey)

* static int ak_skey_set_special_aes_mask(ak_skey skey)

* static int ak_skey_set_special_aes_unmask(ak_skey skey)

* int ak_bckey_create_aes(ak_bckey bkey)
    
Функция для тестирования работоспособности (параметры взяты из стандарта AES FIPS 197):

* void ak_aes128ni_tests()
