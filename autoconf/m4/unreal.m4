#serial 1

dnl Macro: unreal_CHECK_TYPE_SIZES
dnl originally called unet_CHECK_TYPE_SIZES
dnl
dnl Check the size of several types and define a valid int16_t and int32_t.
dnl
AC_DEFUN([unreal_CHECK_TYPE_SIZES],
[dnl Check type sizes
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
if test "$ac_cv_sizeof_int" = 2 ; then
  AC_CHECK_TYPE(int16_t, int)
  AC_CHECK_TYPE(u_int16_t, unsigned int)
elif test "$ac_cv_sizeof_short" = 2 ; then
  AC_CHECK_TYPE(int16_t, short)
  AC_CHECK_TYPE(u_int16_t, unsigned short)
else
  AC_MSG_ERROR([Cannot find a type with size of 16 bits])
fi
if test "$ac_cv_sizeof_int" = 4 ; then
  AC_CHECK_TYPE(int32_t, int)
  AC_CHECK_TYPE(u_int32_t, unsigned int)
elif test "$ac_cv_sizeof_short" = 4 ; then
  AC_CHECK_TYPE(int32_t, short)
  AC_CHECK_TYPE(u_int32_t, unsigned short)
elif test "$ac_cv_sizeof_long" = 4 ; then
  AC_CHECK_TYPE(int32_t, long)
  AC_CHECK_TYPE(u_int32_t, unsigned long)
else
  AC_MSG_ERROR([Cannot find a type with size of 32 bits])
fi
AC_CHECK_SIZEOF(rlim_t)
if test "$ac_cv_sizeof_rlim_t" = 8 ; then
AC_DEFINE([LONG_LONG_RLIM_T], [], [Define if rlim_t is long long])
fi
])

dnl the following 2 macros are based on CHECK_SSL by Mark Ethan Trostler <trostler@juniper.net> 

AC_DEFUN([CHECK_SSL],
[
AC_ARG_ENABLE(ssl,
	[AC_HELP_STRING([--enable-ssl=],[enable ssl will check /usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/sfw /usr/local /usr])],
	[],
	[])
AS_IF([test $enable_ssl = "no"],
	[AC_MSG_ERROR([OpenSSL is required to build RabbitIRCD])])
AS_IF([test $enable_ssl != "no"],
	[ 
	AC_MSG_CHECKING([for openssl])
	for dir in $enable_ssl /usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/sfw /usr/local /usr; do
		ssldir="$dir"
		if test -f "$dir/include/openssl/ssl.h"; then
			AC_MSG_RESULT([found in $ssldir/include/openssl])
			found_ssl="yes";
			if test ! "$ssldir" = "/usr" ; then
				CFLAGS="$CFLAGS -I$ssldir/include";
			fi
			break
		fi
		if test -f "$dir/include/ssl.h"; then
			AC_MSG_RESULT([found in $ssldir/include])
			found_ssl="yes";
			if test ! "$ssldir" = "/usr" ; then
				CFLAGS="$CFLAGS -I$ssldir/include";
			fi
			break
		fi
	done
	if test x_$found_ssl != x_yes; then
		AC_MSG_RESULT(not found)
		echo ""
		echo "Apparently you do not have both the openssl binary and openssl development libraries installed."
		echo "You have two options:"
		echo "a) Install the needed binaries and libraries"
		echo "   and run ./Config"
		echo "OR"
		echo "b) If you don't need SSL..."
		echo "   Run ./Config and say 'no' when asked about SSL"
		echo "   (or pass --disable-ssl to ./configure)"
		echo ""
		exit 1
	else
		CRYPTOLIB="-lssl -lcrypto";
		if test ! "$ssldir" = "/usr" ; then
			LDFLAGS="$LDFLAGS -L$ssldir/lib";
		fi
		AC_DEFINE([USE_SSL], [], [Define if you want to allow SSL connections])
	fi
	])
])
