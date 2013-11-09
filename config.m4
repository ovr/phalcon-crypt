AC_DEFUN([MCRYPT_CHECK_VERSION],[
	old_CPPFLAGS=$CPPFLAGS
	CPPFLAGS=-I$MCRYPT_DIR/include
	AC_MSG_CHECKING(for libmcrypt version)
	AC_EGREP_CPP(yes,
		[
#include <mcrypt.h>
#if MCRYPT_API_VERSION >= 20021217
  yes
#endif
		],
		[AC_MSG_RESULT(>= 2.5.6)],
		[AC_MSG_ERROR(libmcrypt version 2.5.6 or greater required.)]
	)
	CPPFLAGS=$old_CPPFLAGS
])

PHP_ARG_ENABLE([phcrypt], [whether to enable Phalcon Crypt module], [  --enable-phalcon-crypt  Enable Phalcon Crypt module])
if test "$PHP_PHCRYPT" != no; then

dnl
dnl MCrypt
dnl
	PHP_ARG_WITH([mcrypt], [for mcrypt support], [  --with-mcrypt[=DIR]       Include mcrypt support])
	if test "$PHP_MCRYPT" != "no"; then
		for i in $PHP_MCRYPT /usr/local /usr; do
			test -f $i/include/mcrypt.h && MCRYPT_DIR=$i && break
		done

		if test -z "$MCRYPT_DIR"; then
			AC_MSG_ERROR([mcrypt.h not found. Please reinstall libmcrypt.])
		fi

		MCRYPT_CHECK_VERSION

		PHP_CHECK_LIBRARY([mcrypt], [mcrypt_module_open],
			[
				PHP_ADD_LIBRARY(ltdl,, MCRYPT_SHARED_LIBADD)
				AC_DEFINE(HAVE_LIBMCRYPT,1,[ ])
			],
			[
				PHP_CHECK_LIBRARY([mcrypt], [mcrypt_module_open],
					[AC_DEFINE(HAVE_LIBMCRYPT,1,[ ])],
					[AC_MSG_ERROR([Unable to find out libmcrypt version.])],
					[-L$MCRYPT_DIR/$PHP_LIBDIR]
				)
			],
			[-L$MCRYPT_DIR/$PHP_LIBDIR -lltdl]
		)

		PHP_ADD_LIBRARY_WITH_PATH([mcrypt], [$MCRYPT_DIR/$PHP_LIBDIR], [MCRYPT_SHARED_LIBADD])
		PHP_ADD_INCLUDE([$MCRYPT_DIR/include])

		PHP_SUBST([MCRYPT_SHARED_LIBADD])
	fi

dnl
dnl OpenSSL
dnl
	PHP_ARG_WITH(openssl, for OpenSSL support, [  --with-openssl[=DIR]    Include OpenSSL support (requires OpenSSL >= 0.9.6)])

	if test "$PHP_OPENSSL" != "no"; then
		PHP_SUBST(OPENSSL_SHARED_LIBADD)

		AC_CHECK_LIB(ssl, DSA_get_default_method, AC_DEFINE(HAVE_DSA_DEFAULT_METHOD, 1, [OpenSSL 0.9.7 or later]))
		AC_CHECK_LIB(crypto, X509_free, AC_DEFINE(HAVE_DSA_DEFAULT_METHOD, 1, [OpenSSL 0.9.7 or later]))

		PHP_SETUP_OPENSSL(OPENSSL_SHARED_LIBADD,
			[
				AC_DEFINE(HAVE_OPENSSL_EXT,1,[ ])
			],
			[
				AC_MSG_ERROR([OpenSSL check failed. Please check config.log for more information.])
			]
		)
	fi


	PHP_NEW_EXTENSION([phcrypt], [phcrypt.c phcrypt_mcrypt.c], [$ext_shared])
	PHP_ADD_MAKEFILE_FRAGMENT

	PHP_ARG_ENABLE([coverage], [whether to include code coverage symbols], [  --enable-coverage         Enable code coverage symbols], no, no)

	if test "$PHP_COVERAGE" = "yes"; then
		if test "$GCC" != "yes"; then
			AC_MSG_ERROR([GCC is required for --enable-coverage])
		fi

		case `$php_shtool path $CC` in
			*ccache*[)] gcc_ccache=yes;;
			*[)] gcc_ccache=no;;
		esac

		if test "$gcc_ccache" = "yes" && (test -z "$CCACHE_DISABLE" || test "$CCACHE_DISABLE" != "1"); then
			AC_MSG_ERROR([ccache must be disabled when --enable-coverage option is used. You can disable ccache by setting environment variable CCACHE_DISABLE=1.])
		fi

		lcov_version_list="1.5 1.6 1.7 1.9 1.10"

		AC_CHECK_PROG(LCOV, lcov, lcov)
		AC_CHECK_PROG(GENHTML, genhtml, genhtml)
		PHP_SUBST(LCOV)
		PHP_SUBST(GENHTML)

		if test "$LCOV"; then
			AC_CACHE_CHECK([for lcov version], php_cv_lcov_version, [
				php_cv_lcov_version=invalid
				lcov_version=`$LCOV -v 2>/dev/null | $SED -e 's/^.* //'` #'
				for lcov_check_version in $lcov_version_list; do
					if test "$lcov_version" = "$lcov_check_version"; then
						php_cv_lcov_version="$lcov_check_version (ok)"
					fi
				done
			])
		else
			lcov_msg="To enable code coverage reporting you must have one of the following LCOV versions installed: $lcov_version_list"
			AC_MSG_ERROR([$lcov_msg])
		fi

		case $php_cv_lcov_version in
			""|invalid[)]
				lcov_msg="You must have one of the following versions of LCOV: $lcov_version_list (found: $lcov_version)."
				AC_MSG_ERROR([$lcov_msg])
				LCOV="exit 0;"
			;;
		esac

		if test -z "$GENHTML"; then
			AC_MSG_ERROR([Could not find genhtml from the LCOV package])
		fi

		changequote({,})
			CFLAGS=`echo "$CFLAGS" | $SED -e 's/-O[0-9s]*//g'`
			CXXFLAGS=`echo "$CXXFLAGS" | $SED -e 's/-O[0-9s]*//g'`
		changequote([,])

		CFLAGS="$CFLAGS -O0 --coverage"
		CXXFLAGS="$CXXFLAGS -O0 --coverage"
		EXTRA_LDFLAGS="$EXTRA_LDFLAGS -precious-files-regex \.gcno\\\$$"
	fi
fi

