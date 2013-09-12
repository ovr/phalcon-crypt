#ifndef PHCRYPT_MCRYPT_H
#define PHCRYPT_MCRYPT_H

#include "php_phcrypt.h"

extern zend_class_entry* phcrypt_mcrypt_ce;

int init_phcrypt_mcrypt(zend_class_entry* iface TSRMLS_DC);

#endif /* PHCRYPT_MCRYPT_H */
