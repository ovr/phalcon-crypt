#ifndef PHCRYPT_OPENSSL_H
#define PHCRYPT_OPENSSL_H

#include "php_phcrypt.h"

#ifdef PHCRYPT_HAVE_OPENSSL

PHPCRYPT_VISIBILITY_HIDDEN extern zend_class_entry* phcrypt_openssl_ce;

PHPCRYPT_VISIBILITY_HIDDEN int init_phcrypt_openssl(zend_class_entry* iface TSRMLS_DC);
PHPCRYPT_VISIBILITY_HIDDEN void shutdown_phcrypt_openssl(TSRMLS_D);

#endif

#endif /* PHCRYPT_OPENSSL_H */
