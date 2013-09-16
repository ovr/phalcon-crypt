#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "phcrypt_mcrypt.h"

#include <Zend/zend.h>
#include <Zend/zend_exceptions.h>
#include <Zend/zend_interfaces.h>
#include <ext/standard/base64.h>
#include <ext/spl/spl_exceptions.h>
#include <mcrypt.h>
#include <fcntl.h>

#if PHP_WIN32
#include <win32/winutil.h>
#endif

zend_class_entry* phcrypt_mcrypt_ce;

static zend_object_handlers phcrypt_mcrypt_object_handlers;

typedef struct _phcrypt_mcrypt_object {
	zend_object obj;
	char* cipher;
	char* mode;
	char* key;
	uint key_len;
} phcrypt_mcrypt_object;

static inline phcrypt_mcrypt_object* get_object(zval* obj TSRMLS_DC)
{
	return (phcrypt_mcrypt_object*)zend_object_store_get_object(obj TSRMLS_CC);
}

static char* create_iv(size_t size, size_t alloc)
{
	char* iv;

	iv = ecalloc(alloc + 1, 1);
#if PHP_WIN32
	{
		BYTE* iv_b = (BYTE*)iv;
		if (php_win32_get_random_bytes(iv_b, (size_t)size) == FAILURE) {
			efree(iv);
			return NULL;
		}
	}
#else
	{
		size_t read_bytes = 0;
		int fd = open("/dev/urandom", O_RDONLY);
		if (EXPECTED(fd >= 0)) {
			while (read_bytes < size) {
				ssize_t n = read(fd, iv + read_bytes, size - read_bytes);
				if (n < 0) {
					break;
				}

				read_bytes += n;
			}

			close(fd);
		}

		if (UNEXPECTED(read_bytes != size)) {
			efree(iv);
			return NULL;
		}
	}
#endif

	return iv;
}

static int do_encrypt(const char* text, uint text_len, char* cipher, char* mode, const char* key, uint key_len, char** encrypted, uint* encrypted_len TSRMLS_DC)
{
	MCRYPT td;
	int iv_size;
	int key_size;
	int data_size;
	int retval;

	if (!key || !cipher || !mode || !text_len) {
		return FAILURE;
	}

	td = mcrypt_module_open(cipher, PHG(mcrypt_algorithms_dir), mode, PHG(mcrypt_modes_dir));
	if (td == MCRYPT_FAILED) {
		return FAILURE;
	}

	iv_size  = mcrypt_enc_get_iv_size(td);
	key_size = mcrypt_enc_get_key_size(td);

	if (mcrypt_enc_is_block_mode(td)) {
		int block_size = mcrypt_enc_get_block_size(td);
		data_size      = ((text_len - 1) / block_size + 1) * block_size;
	}
	else {
		data_size = text_len;
	}

	if (key_len > key_size) {
		key_len = key_size;
	}

	*encrypted = create_iv(iv_size, iv_size + data_size);
	if (EXPECTED(*encrypted != NULL)) {
		if (EXPECTED(!mcrypt_generic_init(td, (void*)key, (int)key_len, (void*)*encrypted))) {
			memcpy(*encrypted + iv_size, text, text_len);
			mcrypt_generic(td, (void*)(*encrypted + iv_size), data_size);
			*encrypted_len = iv_size + data_size;
			retval = SUCCESS;
			mcrypt_generic_deinit(td);
		}
		else {
			efree(*encrypted);
			retval = FAILURE;
		}
	}
	else {
		retval = FAILURE;
	}

	mcrypt_module_close(td);
	return retval;
}

static int do_decrypt(const char* text, uint text_len, char* cipher, char* mode, const char* key, uint key_len, char** decrypted, uint* decrypted_len TSRMLS_DC)
{
	MCRYPT td;
	int iv_size;
	int key_size;
	int retval;

	if (!key || !cipher || !mode || !text_len) {
		return FAILURE;
	}

	td = mcrypt_module_open(cipher, PHG(mcrypt_algorithms_dir), mode, PHG(mcrypt_modes_dir));
	if (td == MCRYPT_FAILED) {
		return FAILURE;
	}

	iv_size  = mcrypt_enc_get_iv_size(td);
	key_size = mcrypt_enc_get_key_size(td);

	if (mcrypt_enc_is_block_mode(td)) {
		int block_size = mcrypt_enc_get_block_size(td);
		if ((text_len - iv_size) % block_size) {
			mcrypt_module_close(td);
			return FAILURE;
		}
	}

	if (iv_size >= text_len) {
		mcrypt_module_close(td);
		return FAILURE;
	}

	if (key_len > key_size) {
		key_len = key_size;
	}

	*decrypted = ecalloc(text_len - iv_size + 1, 1);

	if (EXPECTED(!mcrypt_generic_init(td, (void*)key, (int)key_len, (void*)text))) {
		memcpy(*decrypted, text + iv_size, text_len - iv_size);
		mdecrypt_generic(td, (void*)*decrypted, text_len - iv_size);
		*decrypted_len = text_len - iv_size;
		mcrypt_generic_deinit(td);
		retval = SUCCESS;
	}
	else {
		retval = FAILURE;
	}

	mcrypt_module_close(td);
	return retval;
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, __construct)
{
	phcrypt_mcrypt_object* obj;

	obj = get_object(getThis() TSRMLS_CC);
	obj->cipher = estrdup("blowfish");
	obj->mode   = estrdup("ncfb");
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, getCipher)
{
	phcrypt_mcrypt_object* obj;

	if (UNEXPECTED(ZEND_NUM_ARGS() != 0)) {
		ZEND_WRONG_PARAM_COUNT();
	}

	obj = get_object(getThis() TSRMLS_CC);
	if (obj->cipher) {
		RETURN_STRING(obj->cipher, 1);
	}

	RETURN_EMPTY_STRING();
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, setCipher)
{
	char* cipher;
	uint cipher_len;
	phcrypt_mcrypt_object* obj;

	if (UNEXPECTED(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &cipher, &cipher_len))) {
		RETURN_NULL();
	}

	obj = get_object(getThis() TSRMLS_CC);
	if (obj->cipher) {
		efree(obj->cipher);
	}

	obj->cipher = estrndup(cipher, cipher_len);
	RETURN_ZVAL(getThis(), 1, 0);
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, getMode)
{
	phcrypt_mcrypt_object* obj;

	if (UNEXPECTED(ZEND_NUM_ARGS() != 0)) {
		ZEND_WRONG_PARAM_COUNT();
	}

	obj = get_object(getThis() TSRMLS_CC);
	if (obj->mode) {
		RETURN_STRING(obj->mode, 1);
	}

	RETURN_EMPTY_STRING();
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, setMode)
{
	char* mode;
	uint mode_len;
	phcrypt_mcrypt_object* obj;

	if (UNEXPECTED(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &mode, &mode_len))) {
		RETURN_NULL();
	}

	obj = get_object(getThis() TSRMLS_CC);
	if (obj->mode) {
		efree(obj->mode);
	}

	obj->mode = estrndup(mode, mode_len);
	RETURN_ZVAL(getThis(), 1, 0);
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, getKey)
{
	phcrypt_mcrypt_object* obj;

	if (UNEXPECTED(ZEND_NUM_ARGS() != 0)) {
		ZEND_WRONG_PARAM_COUNT();
	}

	obj = get_object(getThis() TSRMLS_CC);
	if (obj->key) {
		RETURN_STRINGL(obj->key, obj->key_len, 1);
	}

	RETURN_EMPTY_STRING();
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, setKey)
{
	char* key;
	uint key_len;
	phcrypt_mcrypt_object* obj;

	if (UNEXPECTED(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key, &key_len))) {
		RETURN_NULL();
	}

	obj = get_object(getThis() TSRMLS_CC);
	if (obj->key) {
		efree(obj->key);
	}

	obj->key     = estrndup(key, key_len);
	obj->key_len = key_len;
	RETURN_ZVAL(getThis(), 1, 0);
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, encrypt)
{
	char* text;
	char* key = NULL;
	char* encrypted;
	uint text_len, key_len, encrypted_len;
	phcrypt_mcrypt_object* obj;

	if (UNEXPECTED(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &text, &text_len, &key, &key_len))) {
		RETURN_NULL();
	}

	obj = get_object(getThis() TSRMLS_CC);

	if (!key) {
		key     = obj->key;
		key_len = obj->key_len;
	}

	if (EXPECTED(SUCCESS == do_encrypt(text, text_len, obj->cipher, obj->mode, key, key_len, &encrypted, &encrypted_len TSRMLS_CC))) {
		RETURN_STRINGL(encrypted, encrypted_len, 0);
	}

	RETURN_FALSE;
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, decrypt)
{
	char* text;
	char* key = NULL;
	char* decrypted;
	uint text_len, key_len, decrypted_len;
	phcrypt_mcrypt_object* obj;

	if (UNEXPECTED(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &text, &text_len, &key, &key_len))) {
		RETURN_NULL();
	}

	obj = get_object(getThis() TSRMLS_CC);

	if (!key) {
		key     = obj->key;
		key_len = obj->key_len;
	}

	if (EXPECTED(SUCCESS == do_decrypt(text, text_len, obj->cipher, obj->mode, key, key_len, &decrypted, &decrypted_len TSRMLS_CC))) {
		RETURN_STRINGL(decrypted, decrypted_len, 0);
	}

	RETURN_FALSE;
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, encryptBase64)
{
	char* text;
	char* key = NULL;
	char* encrypted;
	uint text_len, key_len, encrypted_len;
	phcrypt_mcrypt_object* obj;

	if (UNEXPECTED(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &text, &text_len, &key, &key_len))) {
		RETURN_NULL();
	}

	obj = get_object(getThis() TSRMLS_CC);

	if (!key) {
		key     = obj->key;
		key_len = obj->key_len;
	}

	if (EXPECTED(SUCCESS == do_encrypt(text, text_len, obj->cipher, obj->mode, key, key_len, &encrypted, &encrypted_len TSRMLS_CC))) {
		char* encoded;
		int encoded_len;

		encoded = (char*)php_base64_encode((unsigned char*)encrypted, encrypted_len, &encoded_len);
		RETVAL_STRINGL(encoded, encoded_len, 0);
		efree(encrypted);
	}
	else {
		RETURN_FALSE;
	}
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, decryptBase64)
{
	char* text;
	char* key = NULL;
	char* decrypted;
	char* decoded;
	uint text_len, key_len, decrypted_len;
	int decoded_len;
	phcrypt_mcrypt_object* obj;

	if (UNEXPECTED(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &text, &text_len, &key, &key_len))) {
		RETURN_NULL();
	}

	decoded = (char*)php_base64_decode((unsigned char*)text, (int)text_len, &decoded_len);
	if (!decoded) {
		RETURN_FALSE;
	}

	obj = get_object(getThis() TSRMLS_CC);

	if (!key) {
		key     = obj->key;
		key_len = obj->key_len;
	}

	if (EXPECTED(SUCCESS == do_decrypt(decoded, decoded_len, obj->cipher, obj->mode, key, key_len, &decrypted, &decrypted_len TSRMLS_CC))) {
		RETVAL_STRINGL(decrypted, decrypted_len, 0);
	}
	else {
		RETVAL_FALSE;
	}

	efree(decoded);
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, getAvailableCiphers)
{
	char** modules;
	int i, count;

	if (UNEXPECTED(ZEND_NUM_ARGS() != 0)) {
		ZEND_WRONG_PARAM_COUNT();
	}

	modules = mcrypt_list_algorithms(PHG(mcrypt_algorithms_dir), &count);
	array_init_size(return_value, count);
	for (i=0; i<count; ++i) {
		add_next_index_string(return_value, modules[i], 1);
	}

	mcrypt_free_p(modules, count);
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, getAvailableModes)
{
	char** modes;
	int i, count;

	if (UNEXPECTED(ZEND_NUM_ARGS() != 0)) {
		ZEND_WRONG_PARAM_COUNT();
	}

	modes = mcrypt_list_modes(PHG(mcrypt_modes_dir), &count);
	array_init_size(return_value, count);
	for (i=0; i<count; ++i) {
		add_next_index_string(return_value, modes[i], 1);
	}

	mcrypt_free_p(modes, count);
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, __wakeup)
{
	if (UNEXPECTED(ZEND_NUM_ARGS() != 0)) {
		ZEND_WRONG_PARAM_COUNT();
	}

	zend_throw_exception(spl_ce_BadMethodCallException, "Unserialization of 'Phalcon\\Ext\\Crypt\\MCrypt' is not allowed", 0 TSRMLS_CC);
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, serialize)
{
	if (UNEXPECTED(ZEND_NUM_ARGS() != 0)) {
		ZEND_WRONG_PARAM_COUNT();
	}

	RETURN_NULL();
}

static PHP_METHOD(Phalcon_Ext_Crypt_MCrypt, unserialize)
{
	zend_throw_exception(spl_ce_BadMethodCallException, "Unserialization of 'Phalcon\\Ext\\Crypt\\MCrypt' is not allowed", 0 TSRMLS_CC);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_empty, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_setcipher, 0, 0, 1)
	ZEND_ARG_INFO(0, cipher)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_setmode, 0, 0, 1)
	ZEND_ARG_INFO(0, mode)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_setkey, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_endecrypt, 0, 0, 1)
	ZEND_ARG_INFO(0, text)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_unserialize, 0, 0, 1)
	ZEND_ARG_INFO(0, str)
ZEND_END_ARG_INFO()

static
#if ZEND_MODULE_API_NO > 20060613
const
#endif
zend_function_entry phcrypt_mcrypt_class_methods[] = {
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, __construct, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, getCipher, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, setCipher, arginfo_setcipher, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, getMode, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, setMode, arginfo_setmode, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, getKey, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, setKey, arginfo_setkey, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, encrypt, arginfo_endecrypt, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, decrypt, arginfo_endecrypt, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, encryptBase64, arginfo_endecrypt, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, decryptBase64, arginfo_endecrypt, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, getAvailableCiphers, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, getAvailableModes, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, __wakeup, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, serialize, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_MCrypt, unserialize, arginfo_unserialize, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

static void phcrypt_mcrypt_dtor(void* v TSRMLS_DC)
{
	phcrypt_mcrypt_object* obj = v;

	if (obj->cipher) {
		efree(obj->cipher);
	}

	if (obj->mode) {
		efree(obj->mode);
	}

	if (obj->key) {
		efree(obj->key);
	}

	zend_object_std_dtor(&(obj->obj) TSRMLS_CC);
	efree(obj);
}

static zend_object_value phcrypt_mcrypt_ctor(zend_class_entry* ce TSRMLS_DC)
{
	phcrypt_mcrypt_object* obj = ecalloc(1, sizeof(phcrypt_mcrypt_object));
	zend_object_value retval;

	zend_object_std_init(&obj->obj, ce TSRMLS_CC);
#if PHP_VERSION_ID >= 50400
	object_properties_init(&obj->obj, ce);
#endif

	retval.handle = zend_objects_store_put(
		obj,
		(zend_objects_store_dtor_t)zend_objects_destroy_object,
		phcrypt_mcrypt_dtor,
		NULL TSRMLS_CC
	);

	retval.handlers = &phcrypt_mcrypt_object_handlers;
	return retval;
}

HashTable* phcrypt_mcrypt_get_debug_info(zval* object, int* is_temp TSRMLS_DC)
{
	HashTable* ht;
	HashTable* props;
	phcrypt_mcrypt_object* obj;

	props = Z_OBJPROP_P(object);

	ALLOC_HASHTABLE(ht);
	ZEND_INIT_SYMTABLE_EX(ht, 3 + zend_hash_num_elements(props), 0);
	zend_hash_copy(ht, props, (copy_ctor_func_t)zval_add_ref, NULL, sizeof(zval*));

	*is_temp = 1;
	obj = get_object(object TSRMLS_CC);

	if (obj->cipher) {
		zval* tmp;
		MAKE_STD_ZVAL(tmp);
		ZVAL_STRING(tmp, obj->cipher, 1);
		zend_hash_update(ht, "cipher", sizeof("cipher"), (void*)&tmp, sizeof(zval*), NULL);
	}

	if (obj->mode) {
		zval* tmp;
		MAKE_STD_ZVAL(tmp);
		ZVAL_STRING(tmp, obj->mode, 1);
		zend_hash_update(ht, "mode", sizeof("mode"), (void*)&tmp, sizeof(zval*), NULL);
	}

	if (obj->key) {
		zval* tmp;
		MAKE_STD_ZVAL(tmp);
		ZVAL_STRING(tmp, "[set]", 1);
		zend_hash_update(ht, "key", sizeof("key"), (void*)&tmp, sizeof(zval*), NULL);
	}
	else {
		zval* tmp;
		ALLOC_INIT_ZVAL(tmp);
		zend_hash_update(ht, "key", sizeof("key"), (void*)&tmp, sizeof(zval*), NULL);
	}

	return ht;
}

int init_phcrypt_mcrypt(zend_class_entry* iface TSRMLS_DC)
{
	zend_class_entry e;

	INIT_CLASS_ENTRY(e, "Phalcon\\Ext\\Crypt\\MCrypt", phcrypt_mcrypt_class_methods);
	phcrypt_mcrypt_ce = zend_register_internal_class(&e TSRMLS_CC);
	if (EXPECTED(phcrypt_mcrypt_ce != NULL)) {
		phcrypt_mcrypt_ce->ce_flags     |= ZEND_ACC_FINAL_CLASS;
		phcrypt_mcrypt_ce->create_object = phcrypt_mcrypt_ctor;
		phcrypt_mcrypt_ce->serialize     = zend_class_serialize_deny;
		phcrypt_mcrypt_ce->unserialize   = zend_class_unserialize_deny;

		phcrypt_mcrypt_object_handlers = *zend_get_std_object_handlers();
		phcrypt_mcrypt_object_handlers.get_debug_info = phcrypt_mcrypt_get_debug_info;

		if (iface) {
			zend_class_implements(phcrypt_mcrypt_ce TSRMLS_CC, 2, iface, zend_ce_serializable);
		}
		else {
			zend_class_implements(phcrypt_mcrypt_ce TSRMLS_CC, 1, zend_ce_serializable);
		}

		return SUCCESS;
	}

	return FAILURE;
}
