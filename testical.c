/**
 * This is part of a mod_caldav library.
 *
 * Copyright (C) 2006 Nokia Corporation.
 *
 * Contact: Jari Urpalainen <jari.urpalainen@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <ctype.h>
#include <unistd.h>

#include <libxml/tree.h>

#include <libical/ical.h>

#include "mod_caldav.h"
#include "caldav_ical.h"

#define NS_DAV	"DAV:"

static void usage (const char *argv)
{
    fprintf (stdout, "%s -q request_xml_doc -i icalfile\n" \
		     "returns 0 if succeeds, 1 for an error\n", argv);
}

/** main for libical search testings */
int main (int argc, char *argv[])
{
    int opt, rc;
    const char *file = NULL, *ical = NULL;
    xmlDocPtr doc;
    caldav_search_t *p = NULL;
    xmlNodePtr node, caldata = NULL, child = NULL;

    while ((opt = getopt(argc, argv, "q:i:")) != -1) {
	switch (opt) {
	case ':':
	case 'h':
	case '?':
	    usage(argv[0]);
	    return EXIT_SUCCESS;

	case 'q':
	    file = optarg;
	    break;

	case 'i':
	    ical = optarg;
	    break;
	}
    }
    if (file == NULL || ical == NULL) {
	usage(argv[0]);
	return EXIT_FAILURE;
    }
    /* do not prevent the creation of cdata nodes */
    doc = xmlParseFile(file);

    node = doc ? doc->children : NULL;

    for ( ; node; node = node->next) {
	if (NODE_NOT_CALDAV(node))
	    ;
	else if (NODE_MATCH(node, "calendar-query")) {
	    FOR_CHILD(node, node) {
		if (NODE_NOT_DAV(node))
		    ;
		else if (NODE_MATCH(node, "prop"))
		    break;
	    }
	    break;
	}
    }

    FOR_CHILD(caldata, node) {
	if (NODE_NOT_CALDAV(caldata))
	    ;
	else if (NODE_MATCH(caldata, "calendar-data"))
	    break;
    }
    child = node ? node->parent : NULL;
    FOR_CHILD(child, child) {
	if (NODE_MATCH(child, "filter"))
	    break;
    }

    if ((rc = caldav_ical_search(ical, NULL, caldata,
				 child ? child->children : NULL, &p))) {
	char *pch = NULL;

	printf ("%s\n", pch = caldav_ical_dump(p));
	free(pch);
    }
    else {
	printf("search did not find anything\n");
    }

    caldav_ical_free(p);

    xmlFreeDoc(doc);

    xmlCleanupParser();

    return rc ? EXIT_SUCCESS : EXIT_FAILURE;
}

