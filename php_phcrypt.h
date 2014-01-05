#ifndef PHP_PHCRYPT_H
#define PHP_PHCRYPT_H

#include <main/php.h>

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#define PHP_PHCRYPT_EXTNAME  "phcrypt"
#define PHP_PHCRYPT_EXTVER   "0.2"

#ifndef ZEND_MOD_END
#define ZEND_MOD_END { NULL, NULL, NULL, 0 }
#endif

ZEND_BEGIN_MODULE_GLOBALS(phcrypt)
	char* mcrypt_algorithms_dir;
	char* mcrypt_modes_dir;
ZEND_END_MODULE_GLOBALS(phcrypt)

ZEND_EXTERN_MODULE_GLOBALS(phcrypt);

#ifdef ZTS
#define PHG(v)  TSRMG(phcrypt_globals_id, zend_phcrypt_globals*, v)
#else
#define PHG(v)  (phcrypt_globals.v)
#endif

#ifndef EXPECTED
#	define EXPECTED(condition)   (condition)
#	define UNEXPECTED(condition) (condition)
#endif

#if __GNUC__ + 0 >= 4
#	define PHPCRYPT_VISIBILITY_HIDDEN __attribute__((visibility("hidden")))
#else
#	define PHPCRYPT_VISIBILITY_HIDDEN
#endif

#if !defined(PHCRYPT_HAVE_LIBMCRYPT) && !defined(PHCRYPT_HAVE_OPENSSL)
#	error "Neither MCrypt nor OpenSSL is enabled :-("
#endif

#endif /* PHP_PHCRYPT_H */
