#ifndef PHCRYPT_MCRYPT_H
#define PHCRYPT_MCRYPT_H

#include "php_phcrypt.h"

#ifdef PHCRYPT_HAVE_LIBMCRYPT

PHPCRYPT_VISIBILITY_HIDDEN extern zend_class_entry* phcrypt_mcrypt_ce;

PHPCRYPT_VISIBILITY_HIDDEN int init_phcrypt_mcrypt(zend_class_entry* iface TSRMLS_DC);

#endif

#endif /* PHCRYPT_MCRYPT_H */
