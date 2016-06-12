#
# A CalDAV module.
#
# Copyright (C) 2006 Nokia Corporation.
#
# Contact: Jari Urpalainen <jari.urpalainen@nokia.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

# $Id:$

# ----------------------------------------------------------------------
# General options

lib_LTLIBRARIES = mod_caldav.la

# Define the source file for the module
mod_caldav_la_SOURCES = caldav.c caldav_liveprops.c caldav_ical.c

# Define that an include directory is required.
mod_caldav_la_CPPFLAGS = $(APACHE_INC) $(DEPS_MOD_CFLAGS)

# module lib deps
mod_caldav_la_LIBADD = $(DEPS_MOD_LIBS)

# dlopened
mod_caldav_la_LDFLAGS = -avoid-version -module

install-exec-hook:
	install -d $(DESTDIR)$(libdir)/$(APACHE_MODULE_DIR) && \
	mv -f $(DESTDIR)$(libdir)/mod_caldav* $(DESTDIR)$(libdir)/$(APACHE_MODULE_DIR)

uninstall-hook:
	rm -rf $(DESTDIR)$(libdir)/$(APACHE_MODULE_DIR)/mod_caldav*

#libdir = @libdir@/$(APACHE_MODULE_DIR)

caldavdir=$(sysconfdir)/$(APACHE_CONFIG_DIR)
caldav_DATA = dav_caldav.conf dav_caldav.load

TESTS = caldav_tests
noinst_SCRIPTS = caldav_tests

test: check

check_PROGRAMS = testical
testical_SOURCES = testical.c caldav_ical.c
testical_CFLAGS = $(DEPS_XML_CFLAGS) $(DEPS_LIBICAL_CFLAGS)
testical_LDADD = $(DEPS_XML_LIBS) $(DEPS_LIBICAL_LIBS)

