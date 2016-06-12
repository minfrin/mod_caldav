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

#ifndef _CALDAV_ICAL_H_
#define _CALDAV_ICAL_H_

void caldav_ical_freebusy(const char *file,
			  const icaltimezone *tz,
			  icaltimetype start,
			  icaltimetype end,
			  icalcomponent *freebusy);

int caldav_ical_timerange(xmlNodePtr child,
			  icaltimetype *pstart,
			  icaltimetype *pend);

int caldav_ical_search(const char *file,
			const icaltimezone *tz,
			xmlNodePtr caldata,
			xmlNodePtr filter,
			caldav_search_t **p);

char *caldav_ical_dump(caldav_search_t *p);
int caldav_ical_free(caldav_search_t *p);

#endif  /* _CALDAV_ICAL_H_ */
