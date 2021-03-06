dnl ===========================================================================
dnl
dnl configure.in for mod_caldav
dnl Process this file with autoconf to produce a configure script.
dnl
dnl Copyright (C) 2006 Nokia Corporation
dnl
dnl Contact: Jari Urpalainen <jari.urpalainen@nokia.com>
dnl
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Lesser General Public
dnl License as published by the Free Software Foundation; either
dnl version 2.1 of the License, or (at your option) any later version.
dnl
dnl This library is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this library; if not, write to the Free Software
dnl Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
dnl
dnl ===========================================================================

dnl ===========================================================================
dnl Process this file with autoconf to produce a configure script.
dnl ===========================================================================

AC_INIT([mod_caldav],0.3.0)

dnl ===========================================================================
dnl Get host, target and build variables filled with appropriate info.
dnl Validate cache.
dnl ===========================================================================

AC_CANONICAL_HOST

dnl ===========================================================================
dnl Init automake
dnl ===========================================================================

AM_INIT_AUTOMAKE()
AM_CONFIG_HEADER(config.h)

dnl ===========================================================================
dnl Accepted arguments to ./configure...
dnl ===========================================================================

dnl AC_PREFIX_DEFAULT(/usr/local)

dnl ===========================================================================
dnl Checks for programs.
dnl ===========================================================================

AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_CHECK_PROG(RANLIB, ranlib, ranlib, echo)
AC_CHECK_PROG(AR, ar, ar, echo)
AC_CHECK_PROG(LD, ld, ld, echo)
AC_PROG_LIBTOOL
AM_PROG_CC_C_O

dnl ===========================================================================
dnl Checks for header files.
dnl ===========================================================================

AC_HEADER_STDC

AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
if test "$PKG_CONFIG" == "no" ; then
  AC_MSG_ERROR([You should install pkg-config])
fi

PKG_CHECK_MODULES(DEPS, libxml-2.0 apr-1 mod_dav_acl)

PKG_CHECK_MODULES(DEPS_XML, libxml-2.0)

dnl PKG_CHECK_MODULES(DEPS_LIBICAL, libecal-1.2)
PKG_CHECK_MODULES(DEPS_LIBICAL, libical)

DEPS_MOD_CFLAGS="$DEPS_CFLAGS $DEPS_LIBICAL_CFLAGS $CPPFLAGS"
DEPS_MOD_LIBS="$DEPS_LIBS $DEPS_LIBICAL_LIBS $LIBS"
AC_SUBST(DEPS_MOD_CFLAGS)
AC_SUBST(DEPS_MOD_LIBS)

dnl testsuite
PKG_CHECK_MODULES(DEPS_CURL, libcurl glib-2.0)
AC_SUBST(DEPS_CURL_CFLAGS)
AC_SUBST(DEPS_CURL_LIBS)

ACONF=httpd/conf.d
AMODULE=httpd/modules
AINCLUDE=httpd

AC_PATH_PROG(APXS,apxs,no,[$PATH:/usr/sbin/:/usr/local/apache/bin/])
if test "$APXS" = "no"; then
  AC_PATH_PROG(APXS2,apxs2,no,[$PATH:/usr/sbin/:/usr/local/apache/bin/])
  if test "$APXS2" = "no"; then
    AC_MSG_ERROR([apxs(2) is required to build this module])
  fi
  APXS="$APXS2"
  AMODULE=apache2/modules
  ACONF=apache2/mods-available
  AINCLUDE=apache2
fi
APACHE_INC="-I`$APXS -q INCLUDEDIR`"
AC_SUBST(APACHE_INC)

AC_ARG_WITH([apache-config-subdir],
	    [AS_HELP_STRING([--with-apache-config-subdir],
	      [Apache config sub-directory
			   (default is httpd/conf.d (apxs) or
			               apache2/mods-available (apxs2))])],
	    [APACHE_CONFIG_DIR=$withval],
	    [APACHE_CONFIG_DIR=$ACONF])
AC_SUBST(APACHE_CONFIG_DIR)

AC_ARG_WITH([apache-module-subdir],
	    [AS_HELP_STRING([--with-apache-module-subdir],
	      [Apache module sub-directory
			   (default is httpd/modules (apxs) or
				       apache2/modules (apxs2))])],
	    [APACHE_MODULE_DIR=$withval],
	    [APACHE_MODULE_DIR=$AMODULE])
AC_SUBST(APACHE_MODULE_DIR)

AC_ARG_WITH([apache-include-subdir],
	    [AS_HELP_STRING([--with-apache-include-subdir],
	      [Apache include sub-directory
			   (default is httpd (apxs) or
				       apache2 (apxs2))])],
	    [APACHE_INCLUDE_DIR=$withval],
	    [APACHE_INCLUDE_DIR=$AINCLUDE])
AC_SUBST(APACHE_INCLUDE_DIR)


dnl checking for apache patch
save_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS $DEPS_MOD_CFLAGS $APACHE_INC"

PATCH=yes

AC_MSG_CHECKING(if apache patch is required)
AC_TRY_RUN([
#include "httpd.h"
#include "http_protocol.h"

#include "mod_dav.h"

int main (int argc, char **argv)
{
    dav_options_provider opt;

    return 0;
}],[
    PATCH=no
])

if test "$PATCH" = "yes"; then

AC_MSG_CHECKING(deprecated patch)
AC_TRY_RUN([
#include "httpd.h"
#include "http_protocol.h"

#include "mod_dav.h"

int main (int argc, char **argv)
{
    dav_hooks_resource res;

    return 0;
}],[
   AC_DEFINE([APACHE_PATCH], [1], [Enable deprecated apache patch interface])
],[
   AC_MSG_ERROR([You must patch apache before you can use this dav acl module (a required patch is not yet integrated into apache)])
  ])

fi

CFLAGS="$save_CFLAGS"

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [Output debug traces]),
	      [enable_debug=$enableval],[enable_debug=no])

if test "$enable_debug" = "yes"; then
	AC_DEFINE([DEBUG], [1], [Enable tracing])
	AC_MSG_NOTICE([Building standard tracing build])
else
	AC_MSG_NOTICE([Building without tracings])
fi

dnl ===========================================================================
dnl Output files
dnl ===========================================================================

AC_OUTPUT([
Makefile
mod_caldav.spec
])

echo "installing CalDAV module
conf-file-dir: \${sysconfdir}/\$apache-config-subdir ==
               ${sysconfdir}/$APACHE_CONFIG_DIR

module:        \${libdir}/\$apache-module-subdir ==
               ${libdir}/$APACHE_MODULE_DIR

include:       \${includedir}/\$apache-include-subdir ==
               ${includedir}/$APACHE_INCLUDE_DIR

prefix:                ${prefix}
sysconfdir:            ${sysconfdir}
libdir:                ${libdir}
exec_prefix:           ${exec_prefix}
apache-config-subdir:  $APACHE_CONFIG_DIR
apache-module-subdir:  $APACHE_MODULE_DIR
apache-include-subdir: $APACHE_INCLUDE_DIR

look ./configure --help for changing these (in addition to sysconfdir & prefix):
   --with-apache-module-subdir=x
   --with-apache-config-subdir=y
   --with-apache-include-subdir=z
"

if [[ "${prefix:(-4)}" != "/usr" ]]
then
  echo "Probably you want to set the prefix variable (doesn't end into /usr)"
fi
if [[ "${sysconfdir:(-4)}" != "/etc" ]]
then
  echo "Probably you want to set the sysconfdir variable (doesn't end into /etc)"
fi
