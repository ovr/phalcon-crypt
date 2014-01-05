#include "php_phcrypt.h"

#ifdef PHCRYPT_HAVE_OPENSSL

#include "phcrypt_openssl.h"

#include <Zend/zend.h>
#include <Zend/zend_exceptions.h>
#include <Zend/zend_interfaces.h>
#include <ext/standard/base64.h>
#include <ext/spl/spl_exceptions.h>
#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>

#if PHP_WIN32
#include <win32/winutil.h>
#endif

#include "arginfo.h"

zend_class_entry* phcrypt_openssl_ce;

static zend_object_handlers phcrypt_openssl_object_handlers;

typedef struct _phcrypt_openssl_object {
	zend_object obj;
	char* cipher;
	char* key;
	uint key_len;
} phcrypt_openssl_object;

static inline phcrypt_openssl_object* get_object(zval* obj TSRMLS_DC)
{
	return (phcrypt_openssl_object*)zend_object_store_get_object(obj TSRMLS_CC);
}

static char* create_iv(size_t size, size_t alloc)
{
	char* iv;

	iv = ecalloc(alloc + 1, 1);
	if (size) {
#if PHP_WIN32
		BYTE* iv_b = (BYTE*)iv;
		if (php_win32_get_random_bytes(iv_b, (size_t)size) == FAILURE) {
			efree(iv);
			return NULL;
		}
#else
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
#endif
	}

	return iv;
}

static int do_encrypt(const EVP_CIPHER* cipher, const char* text, uint text_len, const char* key, uint key_len, char** encrypted, uint* encrypted_len)
{
	int iv_size;
	int key_size;
	int block_size;
	int written;
	EVP_CIPHER_CTX cipher_ctx;
	int retval;
	unsigned char* out_buf;
	unsigned char* pwd;
	int out_len;

	if (!key || !text_len) {
		return FAILURE;
	}

	iv_size    = EVP_CIPHER_iv_length(cipher);
	key_size   = EVP_CIPHER_key_length(cipher);
	block_size = EVP_CIPHER_block_size(cipher);

	if (key_size > key_len) {
		pwd = ecalloc(key_size, 1);
		memcpy(pwd, key, key_len);
	}
	else {
		pwd = (unsigned char*)key;
	}

	out_len = text_len + block_size;
	out_buf = (unsigned char*)create_iv(iv_size, iv_size + out_len);

	if (EXPECTED(out_buf != NULL)) {
		EVP_EncryptInit(&cipher_ctx, cipher, NULL, NULL);
		if (key_len > key_size) {
			EVP_CIPHER_CTX_set_key_length(&cipher_ctx, key_len);
		}

		EVP_EncryptInit_ex(&cipher_ctx, NULL, NULL, pwd, out_buf);
		EVP_EncryptUpdate(&cipher_ctx, out_buf + iv_size, &written, (const unsigned char*)text, text_len);

		assert(written <= out_len);
		out_len = written;

		if (EVP_EncryptFinal(&cipher_ctx, out_buf + iv_size + out_len, &written)) {
			out_len += written;
			assert(out_len <= text_len + block_size);
			out_buf[iv_size + out_len] = 0;

			*encrypted     = (char*)out_buf;
			*encrypted_len = iv_size + out_len;

			retval = SUCCESS;
		}
		else {
			efree(out_buf);
			retval = FAILURE;
		}

		EVP_CIPHER_CTX_cleanup(&cipher_ctx);
	}
	else {
		TSRMLS_FETCH();
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to create the initialization vector");
		retval = FAILURE;
	}

	if (pwd != (unsigned char*)key) {
		efree(pwd);
	}

	return retval;
}

static int do_decrypt(const EVP_CIPHER* cipher, const char* text, uint text_len, const char* key, uint key_len, char** decrypted, uint* decrypted_len)
{
	int iv_size;
	int key_size;
	int block_size;
	int written;
	int retval;
	EVP_CIPHER_CTX cipher_ctx;
	unsigned char* data;
	int data_len;
	unsigned char* out_buf;
	unsigned char* pwd;
	int out_len;

	if (!key || !text_len) {
		return FAILURE;
	}

	iv_size    = EVP_CIPHER_iv_length(cipher);
	key_size   = EVP_CIPHER_key_length(cipher);
	block_size = EVP_CIPHER_block_size(cipher);

	if (iv_size >= text_len) {
		return FAILURE;
	}

	if (key_size > key_len) {
		pwd = ecalloc(key_size, 1);
		memcpy(pwd, key, key_len);
	}
	else {
		pwd = (unsigned char*)key;
	}

	data     = (unsigned char*)text + iv_size;
	data_len = text_len - iv_size;
	out_len  = data_len + block_size;
	out_buf  = ecalloc(out_len + 1, 1);

	EVP_DecryptInit(&cipher_ctx, cipher, NULL, NULL);
	if (key_len > key_size) {
		EVP_CIPHER_CTX_set_key_length(&cipher_ctx, key_len);
	}

	EVP_DecryptInit_ex(&cipher_ctx, NULL, NULL, pwd, (unsigned char*)text);
	EVP_DecryptUpdate(&cipher_ctx, out_buf, &written, data, data_len);

	assert(written <= out_len);
	out_len = written;

	if (EVP_DecryptFinal(&cipher_ctx, out_buf + out_len, &written)) {
		out_len += written;
		assert(out_len <= data_len + block_size);
		out_buf[out_len]   = 0;
		*decrypted     = (char*)out_buf;
		*decrypted_len = out_len;
		retval = SUCCESS;
	}
	else {
		efree(out_buf);
		retval = FAILURE;
	}

	if (pwd != (unsigned char*)key) {
		efree(pwd);
	}

	EVP_CIPHER_CTX_cleanup(&cipher_ctx);
	return retval;
}

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, __construct)
{
	phcrypt_openssl_object* obj;

	obj = get_object(getThis() TSRMLS_CC);
	obj->cipher = estrdup("AES-256-CFB8");
}

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, getCipher)
{
	phcrypt_openssl_object* obj;

	if (UNEXPECTED(ZEND_NUM_ARGS() != 0)) {
		ZEND_WRONG_PARAM_COUNT();
	}

	obj = get_object(getThis() TSRMLS_CC);
	if (obj->cipher) {
		RETURN_STRING(obj->cipher, 1);
	}

	RETURN_EMPTY_STRING();
}

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, setCipher)
{
	char* cipher;
	uint cipher_len;
	const EVP_CIPHER* cipher_type;

	if (UNEXPECTED(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &cipher, &cipher_len))) {
		RETURN_NULL();
	}

	cipher_type = EVP_get_cipherbyname(cipher);
	if (UNEXPECTED(!cipher_type)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher algorithm");
	}
	else {
		phcrypt_openssl_object* obj = get_object(getThis() TSRMLS_CC);
		if (obj->cipher) {
			efree(obj->cipher);
		}

		obj->cipher = estrndup(cipher, cipher_len);
	}

	RETURN_ZVAL(getThis(), 1, 0);
}

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, getMode)
{
	if (UNEXPECTED(ZEND_NUM_ARGS() != 0)) {
		ZEND_WRONG_PARAM_COUNT();
	}

	RETURN_EMPTY_STRING();
}

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, setMode)
{
	char* mode;
	int mode_len;

	zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &mode, &mode_len);
}

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, getKey)
{
	phcrypt_openssl_object* obj;

	if (UNEXPECTED(ZEND_NUM_ARGS() != 0)) {
		ZEND_WRONG_PARAM_COUNT();
	}

	obj = get_object(getThis() TSRMLS_CC);
	if (obj->key) {
		RETURN_STRINGL(obj->key, obj->key_len, 1);
	}

	RETURN_EMPTY_STRING();
}

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, setKey)
{
	char* key;
	uint key_len;
	phcrypt_openssl_object* obj;

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

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, encrypt)
{
	char* text;
	char* key = NULL;
	char* encrypted;
	uint text_len, key_len, encrypted_len;
	phcrypt_openssl_object* obj;
	const EVP_CIPHER *cipher;

	if (UNEXPECTED(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &text, &text_len, &key, &key_len))) {
		RETURN_NULL();
	}

	obj = get_object(getThis() TSRMLS_CC);

	if (!key) {
		key     = obj->key;
		key_len = obj->key_len;
	}

	cipher = EVP_get_cipherbyname(obj->cipher);
	if (UNEXPECTED(cipher == NULL)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher algorithm");
		RETURN_FALSE;
	}

	if (EXPECTED(SUCCESS == do_encrypt(cipher, text, text_len, key, key_len, &encrypted, &encrypted_len))) {
		RETURN_STRINGL(encrypted, encrypted_len, 0);
	}

	RETURN_FALSE;
}

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, decrypt)
{
	char* text;
	char* key = NULL;
	char* decrypted;
	uint text_len, key_len, decrypted_len;
	phcrypt_openssl_object* obj;
	const EVP_CIPHER *cipher;

	if (UNEXPECTED(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &text, &text_len, &key, &key_len))) {
		RETURN_NULL();
	}

	obj = get_object(getThis() TSRMLS_CC);

	if (!key) {
		key     = obj->key;
		key_len = obj->key_len;
	}

	cipher = EVP_get_cipherbyname(obj->cipher);
	if (UNEXPECTED(cipher == NULL)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher algorithm");
		RETURN_FALSE;
	}

	if (EXPECTED(SUCCESS == do_decrypt(cipher, text, text_len, key, key_len, &decrypted, &decrypted_len))) {
		RETURN_STRINGL(decrypted, decrypted_len, 0);
	}

	RETURN_FALSE;
}

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, encryptBase64)
{
	char* text;
	char* key = NULL;
	char* encrypted;
	uint text_len, key_len, encrypted_len;
	phcrypt_openssl_object* obj;
	const EVP_CIPHER *cipher;

	if (UNEXPECTED(FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &text, &text_len, &key, &key_len))) {
		RETURN_NULL();
	}

	obj = get_object(getThis() TSRMLS_CC);

	if (!key) {
		key     = obj->key;
		key_len = obj->key_len;
	}

	cipher = EVP_get_cipherbyname(obj->cipher);
	if (UNEXPECTED(cipher == NULL)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher algorithm");
		RETURN_FALSE;
	}

	if (EXPECTED(SUCCESS == do_encrypt(cipher, text, text_len, key, key_len, &encrypted, &encrypted_len))) {
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

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, decryptBase64)
{
	char* text;
	char* key = NULL;
	char* decrypted;
	char* decoded;
	uint text_len, key_len, decrypted_len;
	int decoded_len;
	phcrypt_openssl_object* obj;
	const EVP_CIPHER *cipher;

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

	cipher = EVP_get_cipherbyname(obj->cipher);
	if (UNEXPECTED(cipher == NULL)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher algorithm");
		RETURN_FALSE;
	}

	if (EXPECTED(SUCCESS == do_decrypt(cipher, decoded, decoded_len, key, key_len, &decrypted, &decrypted_len))) {
		RETVAL_STRINGL(decrypted, decrypted_len, 0);
	}
	else {
		RETVAL_FALSE;
	}

	efree(decoded);
}

static void openssl_add_method(const OBJ_NAME* name, void* arg)
{
	if (!name->alias) {
		add_next_index_string((zval*)arg, (char*)name->name, 1);
	}
}

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, getAvailableCiphers)
{
	if (UNEXPECTED(ZEND_NUM_ARGS() != 0)) {
		ZEND_WRONG_PARAM_COUNT();
	}

	array_init(return_value);
	OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH, openssl_add_method, return_value);
}

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, getAvailableModes)
{
	if (UNEXPECTED(ZEND_NUM_ARGS() != 0)) {
		ZEND_WRONG_PARAM_COUNT();
	}

	array_init_size(return_value, 0);
}

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, __wakeup)
{
	if (UNEXPECTED(ZEND_NUM_ARGS() != 0)) {
		ZEND_WRONG_PARAM_COUNT();
	}

	zend_throw_exception(spl_ce_BadMethodCallException, "Unserialization of 'Phalcon\\Ext\\Crypt\\OpenSSL' is not allowed", 0 TSRMLS_CC);
}

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, serialize)
{
	if (UNEXPECTED(ZEND_NUM_ARGS() != 0)) {
		ZEND_WRONG_PARAM_COUNT();
	}

	RETURN_NULL();
}

static PHP_METHOD(Phalcon_Ext_Crypt_OpenSSL, unserialize)
{
	zend_throw_exception(spl_ce_BadMethodCallException, "Unserialization of 'Phalcon\\Ext\\Crypt\\OpenSSL' is not allowed", 0 TSRMLS_CC);
}

static
#if ZEND_MODULE_API_NO > 20060613
const
#endif
zend_function_entry phcrypt_openssl_class_methods[] = {
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, __construct, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, getCipher, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, setCipher, arginfo_setcipher, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, getMode, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, setMode, arginfo_setmode, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, getKey, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, setKey, arginfo_setkey, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, encrypt, arginfo_endecrypt, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, decrypt, arginfo_endecrypt, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, encryptBase64, arginfo_endecrypt, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, decryptBase64, arginfo_endecrypt, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, getAvailableCiphers, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, getAvailableModes, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, __wakeup, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, serialize, arginfo_empty, ZEND_ACC_PUBLIC)
	PHP_ME(Phalcon_Ext_Crypt_OpenSSL, unserialize, arginfo_unserialize, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

static void phcrypt_openssl_dtor(void* v TSRMLS_DC)
{
	phcrypt_openssl_object* obj = v;

	if (obj->cipher) {
		efree(obj->cipher);
	}

	if (obj->key) {
		efree(obj->key);
	}

	zend_object_std_dtor(&(obj->obj) TSRMLS_CC);
	efree(obj);
}

static zend_object_value phcrypt_openssl_ctor(zend_class_entry* ce TSRMLS_DC)
{
	phcrypt_openssl_object* obj = ecalloc(1, sizeof(phcrypt_openssl_object));
	zend_object_value retval;

	zend_object_std_init(&obj->obj, ce TSRMLS_CC);
#if PHP_VERSION_ID >= 50400
	object_properties_init(&obj->obj, ce);
#endif

	retval.handle = zend_objects_store_put(
		obj,
		(zend_objects_store_dtor_t)zend_objects_destroy_object,
		phcrypt_openssl_dtor,
		NULL TSRMLS_CC
	);

	retval.handlers = &phcrypt_openssl_object_handlers;
	return retval;
}

static HashTable* phcrypt_openssl_get_debug_info(zval* object, int* is_temp TSRMLS_DC)
{
	HashTable* ht;
	HashTable* props;
	phcrypt_openssl_object* obj;

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

int init_phcrypt_openssl(zend_class_entry* iface TSRMLS_DC)
{
	zend_class_entry e;

	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();

	INIT_CLASS_ENTRY(e, "Phalcon\\Ext\\Crypt\\OpenSSL", phcrypt_openssl_class_methods);
	phcrypt_openssl_ce = zend_register_internal_class(&e TSRMLS_CC);
	if (EXPECTED(phcrypt_openssl_ce != NULL)) {
		phcrypt_openssl_ce->ce_flags     |= ZEND_ACC_FINAL_CLASS;
		phcrypt_openssl_ce->create_object = phcrypt_openssl_ctor;
		phcrypt_openssl_ce->serialize     = zend_class_serialize_deny;
		phcrypt_openssl_ce->unserialize   = zend_class_unserialize_deny;

		phcrypt_openssl_object_handlers = *zend_get_std_object_handlers();
		phcrypt_openssl_object_handlers.get_debug_info = phcrypt_openssl_get_debug_info;

		if (iface) {
			zend_class_implements(phcrypt_openssl_ce TSRMLS_CC, 2, iface, zend_ce_serializable);
		}
		else {
			zend_class_implements(phcrypt_openssl_ce TSRMLS_CC, 1, zend_ce_serializable);
		}

		return SUCCESS;
	}

	return FAILURE;
}

void shutdown_phcrypt_openssl(TSRMLS_D)
{
	EVP_cleanup();
}

#endif /* PHCRYPT_HAVE_OPENSSL */
