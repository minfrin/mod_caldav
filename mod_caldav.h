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
#ifndef _MOD_CALDAV_H_
#define _MOD_CALDAV_H_

#define NS_CALDAV "urn:ietf:params:xml:ns:caldav"

#define XML_VERSION "1.0"

#define NODE_NS(node, ns_string) (node->ns && node->ns->href && \
				  strcmp((char *) node->ns->href, ns_string) == 0)

#define FOR_CHILD(node, parent) \
	for (node = parent ? parent->children : NULL; node; node = node->next)

#define NODE_NOT_DAV(node) node->type != XML_ELEMENT_NODE || !NODE_NS(node, NS_DAV)
#define NODE_NOT_CALDAV(node) node->type != XML_ELEMENT_NODE || !NODE_NS(node, NS_CALDAV)

#define NODE_MATCH(node, y) (strcmp((char *) node->name, y) == 0)

typedef struct caldav_search_s caldav_search_t;


#endif /* _MOD_CALDAV_H_ */
