#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php_phcrypt.h"
#include "phcrypt_mcrypt.h"

#include <main/php.h>
#include <main/php_ini.h>
#include <Zend/zend.h>

ZEND_DECLARE_MODULE_GLOBALS(phcrypt);

PHP_INI_BEGIN()
	STD_PHP_INI_ENTRY("mcrypt.algorithms_dir", NULL, PHP_INI_ALL, OnUpdateString, mcrypt_algorithms_dir, zend_phcrypt_globals, phcrypt_globals)
	STD_PHP_INI_ENTRY("mcrypt.modes_dir",      NULL, PHP_INI_ALL, OnUpdateString, mcrypt_modes_dir,      zend_phcrypt_globals, phcrypt_globals)
PHP_INI_END()

static PHP_MINIT_FUNCTION(phcrypt)
{
	zend_class_entry* phalcon_cryptinterface_ce;
	zend_class_entry** pce;
	REGISTER_INI_ENTRIES();

	if (zend_hash_find(CG(class_table), ZEND_STRS("phalcon\\cryptinterface"), (void **)&pce) == FAILURE) {
		phalcon_cryptinterface_ce = NULL;
	}
	else {
		phalcon_cryptinterface_ce = *pce;
	}

	return init_phcrypt_mcrypt(phalcon_cryptinterface_ce TSRMLS_CC);
}

static PHP_MSHUTDOWN_FUNCTION(phcrypt)
{
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}

static PHP_MINFO_FUNCTION(phcrypt)
{
	DISPLAY_INI_ENTRIES();
}

static
#if ZEND_MODULE_API_NO > 20060613
const
#endif
zend_module_dep phcrypt_deps[] = {
	ZEND_MOD_REQUIRED("spl")
	ZEND_MOD_OPTIONAL("phalcon")
	ZEND_MOD_END
};

zend_module_entry phcrypt_module_entry = {
	STANDARD_MODULE_HEADER_EX,
	ini_entries,
	phcrypt_deps,
	PHP_PHCRYPT_EXTNAME,
	NULL,
	PHP_MINIT(phcrypt),
	PHP_MSHUTDOWN(phcrypt),
	NULL,
	NULL,
	PHP_MINFO(phcrypt),
	PHP_PHCRYPT_EXTVER,
	ZEND_MODULE_GLOBALS(phcrypt),
	NULL,
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_PHCRYPT
ZEND_GET_MODULE(phcrypt)
#endif
