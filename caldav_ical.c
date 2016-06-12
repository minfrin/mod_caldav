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

#include <stdio.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <dlfcn.h>

#include <libical/ical.h>

#include <libxml/tree.h>

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#include "mod_caldav.h"

/** read one line at a time */
char *read_stream(char *s, size_t size, void *d)
{
    return fgets(s, size, d);
}

/** parse ical file */
icalcomponent *parse_text(const char *file)
{
    char *line;
    FILE *stream;
    icalcomponent *c, *root = NULL;
    icalparser *parser;

    stream = fopen(file, "r");
    if (stream == NULL)
	return NULL;

    /* Create a new parser object */
    parser = icalparser_new();

    /* Tell the parser what input routine it should use. */
    icalparser_set_gen_data(parser, stream);

    do {
	/* Get a single content line by making one or more calls to
	 * read_stream()*/
	line = icalparser_get_line(parser, read_stream);

	/* Now, add that line into the parser object. If that line
	 * completes a component, c will be non-zero */
	c = icalparser_add_line(parser, line);

	if (root == NULL)
	    root = c;

	icalmemory_free_buffer(line);

    } while (line != 0) ;

    fclose(stream);
    icalparser_free(parser);
    return root;
}

/** create new span */
static icaltime_span span_new(struct icaltimetype dtstart,
                              struct icaltimetype dtend, int is_busy)
{
    icaltime_span span;

    span.is_busy = is_busy;
    span.start = icaltime_as_timet_with_zone(dtstart, dtstart.zone);

    if (icaltime_is_null_time(dtend)) {
	if (!icaltime_is_date(dtstart)) {
	    /* If dtstart is a DATE-TIME and there is no DTEND nor DURATION
	     * it takes no time */
	    span.end = span.start;
	    return span;
	}
	else {
	    dtend = dtstart;
	}
    }

    span.end = icaltime_as_timet_with_zone(dtend, dtend.zone);

    if (icaltime_is_date(dtstart))
	/* no time specified, go until the end of the day..*/
	span.end += 60 * 60 * 24 - 1;

    return span;
}

typedef enum {
    FREEBUSY_FREE = 0,
    FREEBUSY_BUSY,
    FREEBUSY_TENTATIVE
} busy_t;

/* is busy evaluation */
static int is_busy(icalcomponent *comp)
{
    icalproperty *transp;
    enum icalproperty_status status;
    busy_t ret = FREEBUSY_BUSY;

    /** @todo check access control here, converting busy->free if the
	permissions do not allow access... */

    /* Is this a busy time?  Check the TRANSP property */
    transp = icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);

    if (transp) {
	icalvalue *transp_val = icalproperty_get_value(transp);

	switch (icalvalue_get_transp(transp_val)) {
	case ICAL_TRANSP_OPAQUE:
	case ICAL_TRANSP_OPAQUENOCONFLICT:
	case ICAL_TRANSP_NONE:
	    ret = FREEBUSY_BUSY;
	    break;

	case ICAL_TRANSP_TRANSPARENT:
	case ICAL_TRANSP_TRANSPARENTNOCONFLICT:
	    ret = FREEBUSY_FREE;
	    break;

	default:
	    ret = FREEBUSY_FREE;
	    break;
	}
    }
    status = icalcomponent_get_status(comp);

    if (ret && status) {
	switch (status) {
	case ICAL_STATUS_CANCELLED:
	    ret = FREEBUSY_FREE;
	    break;

	case ICAL_STATUS_TENTATIVE:
	    ret = FREEBUSY_TENTATIVE;
	    break;

	default:
	    break;
	}
    }

    return ret;
}

/** convert time with tzid parameter */
static struct icaltimetype get_datetime(icalcomponent *comp, icalproperty *prop)
{
    icalcomponent *c;
    icalparameter *param;
    struct icaltimetype ret;

    ret = icalvalue_get_datetime(icalproperty_get_value(prop));

    param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);

    if (param != NULL) {
	const char *tzid = icalparameter_get_tzid(param);
	icaltimezone *tz = NULL;

	for (c = comp; c != NULL; c = icalcomponent_get_parent(c)) {
	    tz = icalcomponent_get_timezone(c, tzid);

	    if (tz != NULL)
		break;
	}
	if (tz == NULL)
	    tz = icaltimezone_get_builtin_timezone_from_tzid(tzid);

	if (tz != NULL)
	    ret = icaltime_set_timezone(&ret, tz);
    }

    return ret;
}

/**
 * recurrence callback routine
*/
void component_foreach_recurrence(icalcomponent* comp,
                                  const icaltimezone *tz,
                                  icaltime_span *limit,
                                  void (*callback)(icalcomponent *comp,
                                                   int first,
                                                   icaltime_span *span,
                                                   icaltime_span *limit,
                                                   void *data),
                                  void *callback_data)
{
    struct icaltimetype dtstart, dtend;
    icaltime_span recurspan, basespan;
    int dtduration;
    icalproperty *rrule, *rdate;
    struct icaldurationtype dur;

    if (comp == NULL || callback == NULL)
	return;

    dtstart = icalcomponent_get_dtstart(comp);
    if (icaltime_is_null_time(dtstart) &&
	icalcomponent_isa(comp) != ICAL_VTODO_COMPONENT)
	return;

    if (!icaltime_is_utc(dtstart) && dtstart.zone == NULL)
	dtstart = icaltime_set_timezone(&dtstart, tz);

    /* The end time could be specified as either a DTEND or a DURATION */
    /* icalcomponent_get_dtend takes care of these cases. */
    dtend = icalcomponent_get_dtend(comp);
    if (icaltime_is_null_time(dtend) &&
	icalcomponent_isa(comp) == ICAL_VTODO_COMPONENT) {
	icalproperty *due =
		icalcomponent_get_first_property(comp, ICAL_DUE_PROPERTY);

	if (due)
	    dtend = get_datetime(comp, due);
    }
    if (!icaltime_is_utc(dtend) && dtend.zone == NULL)
	dtend = icaltime_set_timezone(&dtend, tz);

    /* Now set up the base span for this item, corresponding to the
     * base DTSTART and DTEND */
    basespan = span_new(dtstart, dtend, TRUE);
    basespan.is_busy = is_busy(comp);

    /* Do the callback for the initial DTSTART entry */
    if (!icalproperty_recurrence_is_excluded(comp, &dtstart, &dtstart))
	/** call callback action **/
	callback(comp, TRUE, &basespan, limit, callback_data);
    else if (icalcomponent_isa(comp) == ICAL_VTODO_COMPONENT)
	callback(comp, TRUE, &basespan, limit, callback_data);

    recurspan = basespan;
    dtduration = basespan.end - basespan.start;

    /* Now cycle through the rrule entries */
    for (rrule = icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY);
	 rrule != NULL;
	 rrule = icalcomponent_get_next_property(comp, ICAL_RRULE_PROPERTY)) {

	struct icalrecurrencetype recur = icalproperty_get_rrule(rrule);
	icalrecur_iterator *rrule_itr = icalrecur_iterator_new(recur, dtstart);
	struct icaltimetype rrule_time;

	while (TRUE) {
	    rrule_time = icalrecur_iterator_next(rrule_itr);

	    if (icaltime_is_null_time(rrule_time))
		break;

	    if (!icaltime_compare(rrule_time, dtstart))
		continue;

	    dur = icaltime_subtract(rrule_time, dtstart);

	    recurspan.start = basespan.start + icaldurationtype_as_int(dur);
	    recurspan.end = recurspan.start + dtduration;

	    if (!icalproperty_recurrence_is_excluded(comp, &dtstart, &rrule_time))
		/** call callback action **/
		callback(comp, FALSE, &recurspan, limit, callback_data);
	} /* end of iteration over a specific RRULE */

	icalrecur_iterator_free(rrule_itr);
    } /* end of RRULE loop */

    /** Now process RDATE entries **/
    for (rdate = icalcomponent_get_first_property(comp, ICAL_RDATE_PROPERTY);
	 rdate != NULL;
	 rdate = icalcomponent_get_next_property(comp, ICAL_RDATE_PROPERTY)) {

	struct icaldatetimeperiodtype rdate_period = icalproperty_get_rdate(rdate);

	/**
	 * RDATES can specify raw datetimes, periods, or dates.
	 * we only support raw datetimes for now..
	 * @todo Add support for other types
	 */
	if (icaltime_is_null_time(rdate_period.time))
	    continue;

	dur = icaltime_subtract(rdate_period.time, dtstart);

	recurspan.start = basespan.start + icaldurationtype_as_int(dur);
	recurspan.end = recurspan.start + dtduration;

	if (!icalproperty_recurrence_is_excluded(comp, &dtstart, &rdate_period.time))
	    /** call callback action **/
	    callback(comp, FALSE, &recurspan, limit, callback_data);
    }
}

/** freebusy structure for callbacks */
typedef struct _freebusy_cb
{
    icalcomponent *vfreebusy;
    icalcomponent **list;
    int count;
} freebusy_cb_t;

/** add freebusy property if time overlaps */
static void freebusy_callback(icalcomponent *comp, int first,
                              struct icaltime_span *span,
                              struct icaltime_span *limit, void *data)
{
    freebusy_cb_t *fb = data;
    icalcomponent *vfreebusy = fb->vfreebusy;

    if (icaltime_span_overlaps(span, limit) == FALSE)
	return;

    span->is_busy = is_busy(comp);

    if (span->is_busy != FREEBUSY_FREE) {
	struct icalperiodtype per;
	icalproperty *property;

	per.duration = icaldurationtype_from_int(span->end - span->start);
	per.start = icaltime_from_timet(span->start, 0);
	per.end = icaltime_from_timet(span->end, 0);
	per.end.is_utc = per.start.is_utc = TRUE;

	/* check instantiated list */
	if (fb->list) {
	    icalproperty *prop = icalcomponent_get_first_property(comp, ICAL_UID_PROPERTY);
	    const char *pcsz = icalproperty_get_uid(prop);
	    int i;

	    for (i = 0; i < fb->count; i++) {
		prop = icalcomponent_get_first_property(fb->list[i], ICAL_UID_PROPERTY);
		const char *instance = icalproperty_get_uid(prop);

		if (pcsz && instance && strcmp(instance, pcsz) == 0) {
		    prop = icalcomponent_get_first_property(fb->list[i],
							    ICAL_RECURRENCEID_PROPERTY);
		    icaltimetype recur = get_datetime(comp, prop);

		    if (!icaltime_is_utc(recur))
			recur = icaltime_convert_to_zone(recur,
							 icaltimezone_get_utc_timezone());
		    /* recurrence replaced/instantiated ? */
		    if (!icaltime_compare(per.start, recur))
			return;
		}
	    }
	}
	icalcomponent_add_property(vfreebusy,
				   property = icalproperty_new_freebusy(per));
	if (span->is_busy == FREEBUSY_TENTATIVE)
	    icalproperty_add_parameter(property,
					icalparameter_new_fbtype(ICAL_FBTYPE_BUSYTENTATIVE));
    }
}

/** return span in time_t format */
static icaltime_span get_limit_span(icaltimetype start, icaltimetype end)
{
    icaltime_span limit = { 0 };

    /* Calculate the ceiling and floor values.. */
    limit.start = icaltime_as_timet_with_zone(start, icaltimezone_get_utc_timezone());

    if (!icaltime_is_null_time (end))
	limit.end = icaltime_as_timet_with_zone(end, icaltimezone_get_utc_timezone());
    else
	limit.end = INT_MAX;  /* max 32 bit time_t */

    return limit;
}

/** add component pointer to filter list */
static void add_component_to_list(icalcomponent *p,
                                  icalcomponent ***list, int *pc)
{
    int i;

    for (i = 0; i < *pc; i++) {
	if ((p == list[0][i]))
	    break;
    }

    if (i == *pc) {
	*list = realloc(*list, (*pc + 1) * sizeof (**list));

	list[0][pc[0]++] = p;
    }
}

/** calculate vfreebusy */
void caldav_ical_freebusy(const char *file, const icaltimezone *tz,
                          icaltimetype start, icaltimetype end,
                          icalcomponent *vfreebusy)
{
    icalcomponent *root = parse_text(file);
    icalcomponent *event;
    icaltime_span limit = get_limit_span(start, end);
    freebusy_cb_t fb = { 0 };

    for (event = icalcomponent_get_first_component(root, ICAL_VEVENT_COMPONENT);
	 event != NULL;
	 event = icalcomponent_get_next_component(root, ICAL_VEVENT_COMPONENT)) {

	icalproperty *prop = icalcomponent_get_first_property(event, ICAL_RECURRENCEID_PROPERTY);

	if (prop)
	    add_component_to_list(event, &fb.list, &fb.count);
    }
    fb.vfreebusy = vfreebusy;

    for (event = icalcomponent_get_first_component(root, ICAL_VEVENT_COMPONENT);
	 event != NULL;
	 event = icalcomponent_get_next_component(root, ICAL_VEVENT_COMPONENT))
	component_foreach_recurrence(event, tz, &limit, freebusy_callback, &fb);

    if (root)
	icalcomponent_free(root);

    free(fb.list);
}

/** convert utc time range into libical types */
int caldav_ical_timerange(xmlNodePtr child, icaltimetype *start,
                          icaltimetype *end)
{
    xmlChar *pch = xmlGetProp(child, (const xmlChar *) "start");

    if (pch)
	*start = icaltime_from_string((char *) pch);
    else
	*start = icaltime_from_string("19700101000000Z");
    xmlFree(pch);

    pch = xmlGetProp(child, (const xmlChar *)"end");
    if (pch)
	*end = icaltime_from_string((char *) pch);
    else
	*end = icaltime_from_string("30000101000000Z");  /* ;-) */
    xmlFree(pch);

    return 0;
}

/** simple overlap exists, return boolean change */
static void overlap_callback(icalcomponent *comp, int first,
                             struct icaltime_span *span,
                             struct icaltime_span *limit, void *data)
{
    if (icaltime_span_overlaps(span, limit) == FALSE)
	return;
    {
	int *p = data;

	*p = TRUE;
    }
}

/** check for time range match */
static int range_match(icalcomponent *c, const icaltimezone *tz,
                       struct icaltime_span *limit,
                       struct icaltimetype dtstart,
                       struct icaltimetype dtend)
{
    icaltime_span basespan;

    if (!icaltime_is_utc(dtstart) && dtstart.zone == NULL)
	dtstart = icaltime_set_timezone(&dtstart, tz);

    if (!icaltime_is_utc(dtend) && dtend.zone == NULL)
	dtend = icaltime_set_timezone(&dtend, tz);

    basespan = span_new(dtstart, dtend, TRUE);

    if (icaltime_span_overlaps(&basespan, limit))
	return TRUE;

    return FALSE;
}

/** TODO time range evaluations */
static int todo_time_range(icalcomponent* inner, const icaltimezone *tz,
                           icaltime_span *limit)
{
    icalproperty *start_prop = icalcomponent_get_first_property(inner, ICAL_DTSTART_PROPERTY);
    icalproperty *dur_prop = icalcomponent_get_first_property(inner, ICAL_DURATION_PROPERTY);
    icalproperty *due_prop = icalcomponent_get_first_property(inner, ICAL_DUE_PROPERTY);
    icalproperty *compl_prop = icalcomponent_get_first_property(inner, ICAL_COMPLETED_PROPERTY);
    icalproperty *creat_prop = icalcomponent_get_first_property(inner, ICAL_CREATED_PROPERTY);
    struct icaltimetype dtstart, dtend;

    if (start_prop != NULL) {
	dtstart = icalcomponent_get_dtstart(inner);

	if (dur_prop != NULL) {
	    struct icaldurationtype duration = icalproperty_get_duration(dur_prop);

	    dtend = icaltime_add(dtstart, duration);
	}
	else {
	    dtend = dtstart;
	}

	/* TEST */
	if (range_match(inner, tz, limit, dtstart, dtend))
	    return TRUE;
    }

    if (due_prop != NULL) {
	dtend = icalproperty_get_due(due_prop);

	if (start_prop == NULL)
	    dtstart = dtend;

	if (range_match(inner, tz, limit, dtstart, dtend))
	    return TRUE;
    }

    if (creat_prop)
	dtstart = icalproperty_get_created(creat_prop);

    if (compl_prop)
	dtend = icalproperty_get_completed(compl_prop);

    if (creat_prop && compl_prop) {
	if (range_match(inner, tz, limit, dtstart, dtend))
	    return TRUE;
    }
    else if (compl_prop) {
	if (range_match(inner, tz, limit, dtend, dtend))
	    return TRUE;
    }
    else if (creat_prop) {
	/* different than in the spec */
	if (range_match(inner, tz, limit, dtstart, dtstart))
	    return TRUE;
    }
    else if (creat_prop == NULL && compl_prop == NULL && due_prop == NULL &&
	     start_prop == NULL) {
	return TRUE;
    }

    return FALSE;
}

typedef struct _alarm_overlap
{
    struct icaltriggertype tr;
    struct icaldurationtype dur;
    int count, overlap;
    icalparameter_related related;
} alarm_overlap_t;

/** valarm overlap checking */
static void alarm_overlap_callback(icalcomponent *comp, int first,
                                   struct icaltime_span *span,
                                   struct icaltime_span *limit,
                                   void *data)
{
    alarm_overlap_t *ao = data;
    time_t t;
    int i, c = icaldurationtype_as_int(ao->dur);
    struct icaltime_span sp[1] = { *span };

    if (!icaltime_is_null_time(ao->tr.time)) {
	t = icaltime_as_timet_with_zone(ao->tr.time,
					icaltimezone_get_utc_timezone());
    }
    else {
	if (ao->related == ICAL_RELATED_START)
	    t = sp->start;
	else
	    t = sp->end;
    }

    for (i = 0; i < ao->count; i++) {
	/* abs utc time */
	sp->end = sp->start = t + i * c + icaldurationtype_as_int(ao->tr.duration);

	if (icaltime_span_overlaps(sp, limit))
	    ao->overlap = TRUE;
    }
}

/** text match checkings */
static int text_matches(xmlNodePtr node, const char *pch)
{
    xmlChar *collation = xmlGetProp(node, (const xmlChar *) "collation");
    xmlChar *invert = xmlGetProp(node, (const xmlChar *) "negate-condition");
    xmlChar *value = xmlNodeGetContent(node);
    int rc = FALSE;

    if (collation == NULL || strcasecmp((char *) collation, "i;ascii-casemap") == 0)
	rc = (value && pch && xmlStrcasestr((xmlChar *) pch, value)) ? TRUE : FALSE;
    else if (strcasecmp((char *) collation, "i;octet") == 0)
	rc = (value && pch && xmlStrstr((xmlChar *) pch, value)) ? TRUE : FALSE;

    if (invert && strcasecmp((char *) invert, "yes") == 0)
	rc = !rc;

    xmlFree(value);
    xmlFree(invert);
    xmlFree(collation);

    return rc;
}

/** property tests */
static int prop_tests(xmlNodePtr node, icalcomponent *c, const icaltimezone *tz,
                      icalproperty *iprop)
{
    xmlNodePtr prop = NULL;

    FOR_CHILD(prop, node) {
	if (NODE_NOT_CALDAV(prop)) {
	    ;
	}
	else if (NODE_MATCH(prop, "is-not-defined"))  {
	    if (iprop)
		return FALSE;
	}
	else if (NODE_MATCH(prop, "time-range"))  {
	    icaltimetype start, end, dtime;
	    icaltime_span basespan, limit;
	    icalproperty_kind kind;

	    caldav_ical_timerange(prop, &start, &end);
	    limit = get_limit_span(start, end);
	    kind = icalproperty_isa(iprop);

	    if (kind == ICAL_DTEND_PROPERTY || kind == ICAL_DUE_PROPERTY)
		dtime = icalcomponent_get_dtend(c);
	    else if (kind == ICAL_DTSTART_PROPERTY)
		dtime = icalcomponent_get_dtstart(c);
	    else if (kind == ICAL_COMPLETED_PROPERTY ||
		     kind == ICAL_CREATED_PROPERTY ||
		     kind == ICAL_DTSTAMP_PROPERTY ||
		     kind == ICAL_LASTMODIFIED_PROPERTY)
		dtime = get_datetime(c, iprop);
	    else
		dtime = icaltime_null_time();

	    if (!icaltime_is_utc(dtime) && dtime.zone == NULL)
		dtime = icaltime_set_timezone(&dtime, tz);

	    basespan = span_new(dtime, dtime, TRUE);

	    if (!icalproperty_recurrence_is_excluded(c, &dtime, &dtime) &&
			icaltime_span_overlaps(&basespan, &limit) == FALSE)
		return FALSE;
	}
	else if (NODE_MATCH(prop, "text-match")) {
	    char *val;

	    if (iprop == NULL)
		return FALSE;

	    val = icalproperty_get_value_as_string_r(iprop);

	    if (text_matches(prop, val) == FALSE) {
		free(val);
		return FALSE;
	    }

	    free(val);
	}
	else if (NODE_MATCH(prop, "param-filter")) {
	    xmlChar *pch = xmlGetProp(prop, (const xmlChar *) "name");
	    xmlNodePtr param;
	    int f = FALSE;
	    icalparameter_kind ev = icalparameter_string_to_kind((char *) pch);
	    icalparameter *iparam;

	    for (iparam = icalproperty_get_first_parameter(iprop, ev);
		 f == FALSE && iparam != NULL;
		 iparam = icalproperty_get_next_parameter(iprop, ev)) {

		FOR_CHILD(param, prop) {
		    if (NODE_NOT_CALDAV(param)) {
			;
		    }
		    else if (NODE_MATCH(param, "is-not-defined")) {
			break;
		    }
		    else if (NODE_MATCH(param, "text-match")) {
			const char *sz =
				icalparameter_enum_to_string(icalparameter_get_value(iparam));

			if (sz == NULL)
			    sz = icalparameter_get_xvalue(iparam);

			if (text_matches(param, sz))
			    f = TRUE;
		    }
		}
	    }
	    xmlFree(pch);

	    if (f == FALSE)
		return FALSE;
	}
    }
    return TRUE;
}

/**
 * recursive search of components based on given <filter> rules
*/
static int caldav_ical_recursion(icalcomponent *c, const icaltimezone *tz,
                                 xmlNodePtr filter, icalcomponent ***ppp,
                                 int *pc)
{
    xmlNodePtr node, *node_child = NULL;
    int i, count_child = 0;
    icalcomponent **pp = *ppp;

    for (node = filter; node != NULL; node = node->next) {
	if (NODE_NOT_CALDAV(node))
	    ;
	else if (NODE_MATCH(node, "comp-filter"))  {
	    xmlChar *pch = xmlGetProp(node, (const xmlChar *) "name");
	    int component = TRUE;
	    icalcomponent *parent = c;
	    icalcomponent_kind ev;

	    if (pch == NULL)
		return -1;

	    ev = icalcomponent_string_to_kind((char *) pch);

	    if (ev != ICAL_VCALENDAR_COMPONENT)
		c = icalcomponent_get_first_component(c, ev);

	    for ( ; c != NULL; c = icalcomponent_get_next_component(parent, ev)) {
		xmlNodePtr prop;

		FOR_CHILD(prop, node) {
		    if (NODE_NOT_CALDAV(prop)) {
			;
		    }
		    else if (NODE_MATCH(prop, "is-not-defined")) {
			if (c)
			    component = FALSE;
		    }
		    else if (NODE_MATCH(prop, "time-range")) {
			icaltimetype start, end;
			icaltime_span limit;

			caldav_ical_timerange(prop, &start, &end);
			limit = get_limit_span(start, end);

			if (ev == ICAL_VEVENT_COMPONENT) {
			    int f = FALSE;

			    component_foreach_recurrence(c, tz, &limit, overlap_callback, &f);

			    if (f == FALSE)
				component = FALSE;
			}
			else if (ev == ICAL_VTODO_COMPONENT) {
			    if (todo_time_range(c, tz, &limit) == FALSE)
				component = FALSE;
			}
			else if (ev == ICAL_VJOURNAL_COMPONENT) {
			    struct icaltimetype dtstart, dtend;

			    dtstart = icalcomponent_get_dtstart(c);

			    if (icaltime_is_date(dtstart)) {
				dtstart.is_date = FALSE;
				dtend = icaltime_add(dtstart, icaldurationtype_from_int(86400));
			    }
			    else {
				dtend = dtstart;
			    }
			    if (range_match(c, tz, &limit, dtstart, dtend) == FALSE)
				component = FALSE;
			}
			else if (ev == ICAL_VFREEBUSY_COMPONENT) {
			    struct icaltimetype dtstart, dtend;
			    icaltime_span basespan;
			    int f = FALSE;
			    icalproperty *iprop;

			    dtstart = icalcomponent_get_dtstart(c);
			    if (icaltime_is_null_time(dtstart)) {
				;
			    }
			    else {
				dtend = icalcomponent_get_dtend(c);

				if (range_match(c, tz, &limit, dtstart, dtend) == FALSE)
				    component = FALSE;
			    }

			    for (iprop = icalcomponent_get_first_property(c, ICAL_FREEBUSY_PROPERTY);
				 iprop != NULL && f == FALSE && component;
				 iprop = icalcomponent_get_next_property(c, ICAL_FREEBUSY_PROPERTY)) {
				struct icalperiodtype per = icalproperty_get_freebusy(iprop);

				if (!icaltime_is_null_time(per.end))
				    basespan = span_new(per.start, per.end, TRUE);
				else
				    basespan = span_new(per.start, icaltime_add(per.start, per.duration), TRUE);

				if (icaltime_span_overlaps(&basespan, &limit))
				    f = TRUE;
			    }
			    if (f == FALSE)
				component = FALSE;
			}
			else if (ev == ICAL_VALARM_COMPONENT) {
			    icalproperty *iprop;
			    alarm_overlap_t ao[1];

			    memset(ao, 0, sizeof (ao));
			    ao->related = ICAL_RELATED_START;

			    iprop = icalcomponent_get_first_property(c, ICAL_TRIGGER_PROPERTY);
			    if (iprop) {
				icalparameter *param;

				ao->tr = icalproperty_get_trigger(iprop);

				param = icalproperty_get_first_parameter(iprop,
									 ICAL_RELATED_PARAMETER);
				if (param != NULL)
				    ao->related = icalparameter_get_related(param);
			    }
			    iprop = icalcomponent_get_first_property(c, ICAL_DURATION_PROPERTY);
			    if (iprop)
				ao->dur = icalproperty_get_duration(iprop);

			    iprop = icalcomponent_get_first_property(c, ICAL_REPEAT_PROPERTY);
			    ao->count = iprop ? icalproperty_get_repeat(iprop) + 1 : 1;

			    component_foreach_recurrence(icalcomponent_get_parent(c), tz, &limit,
							 alarm_overlap_callback, ao);
			    if (ao->overlap == FALSE)
				component = FALSE;
			}
		    }
		    else if (NODE_MATCH(prop, "prop-filter")) {
			xmlChar *pch = xmlGetProp(prop, (const xmlChar *) "name");
			int f = FALSE;
			icalproperty_kind ev;
			icalproperty *iprop;

			if (pch == NULL)
			    component = FALSE;

			ev = icalproperty_string_to_kind((char *) pch);
			iprop = icalcomponent_get_first_property(c, ev);

			do {
			    if (prop_tests(prop, c, tz, iprop))
				f = TRUE;

			    iprop = icalcomponent_get_next_property(c, ev);
			} while (iprop && f == FALSE)
			    ;
			xmlFree(pch);

			if (f == FALSE)
			    component = FALSE;
		    }
		    else if (NODE_MATCH(prop, "comp-filter"))  {
			node_child = realloc(node_child,
				(count_child + 1) * sizeof(*node_child));
			node_child[count_child++] = prop;
		    }
		}

		if (component) {
		    for (i = 0; i < count_child; i++)
			caldav_ical_recursion(c, tz, node_child[i], ppp, pc);

		    if (!count_child) {
			*ppp = pp = realloc(pp, (*pc + 1) * sizeof(*pp));
			pp[pc[0]++] = c;
		    }
		}

		free(node_child);
		node_child = NULL;
		count_child = 0;
	    }
	    xmlFree(pch);
	}
    }
    return 0;
}

typedef enum {
    REPORT_LIMIT_RECUR = 0,
    REPORT_LIMIT_FREEBUSY,
    REPORT_EXPAND,
    REPORT_ALL
} report_enum_t;

/** remove components not on a filter list */
static icalcomponent *remove_comps_not_found(icalcomponent *parent,
                                             icalcomponent *c,
                                             icalcomponent **list, int count)
{
    for ( ; c != NULL; ) {
	int i;

	for (i = 0; i < count; i++) {
	    if (list[i] == c)
		break;
	}

	/* component not found -> remove it */
	if (i == count) {
	    icalcomponent *next =
		icalcomponent_get_next_component(parent, ICAL_ANY_COMPONENT);

	    if (parent != c)
		icalcomponent_remove_component(parent, c);
	    else
		parent = NULL;

	    icalcomponent_free(c);
	    c = next;
	}
	else {
	    icalcomponent *cc =
		icalcomponent_get_first_component(c, ICAL_ANY_COMPONENT);

	    for ( ; cc != NULL;
		 cc = icalcomponent_get_next_component(c, ICAL_ANY_COMPONENT))
		remove_comps_not_found(c, cc, list, count);

	    c = icalcomponent_get_next_component(parent, ICAL_ANY_COMPONENT);
	}
    }

    return parent;
}

/**
 * remove NOT requested properties and components
 * based on <comp> and <prop> values
 */
static icalcomponent *show_requested_comps(icalcomponent *parent,
                                           icalcomponent *c,
                                           xmlNodePtr node)
{
    do {
	int all_props = -1, all_comps = -1;
	const char *value = c != NULL ?
		icalcomponent_kind_to_string(icalcomponent_isa(c)) : NULL;
	xmlNodePtr n = NULL, child = NULL;

	FOR_CHILD(n, node) {
	    if (NODE_NOT_CALDAV(n)) {
		;
	    }
	    else if (NODE_MATCH(n, "prop")) {
		all_props = FALSE;
	    }
	    else if (NODE_MATCH(n, "allprop")) {
		all_props = TRUE;
	    }
	    else if (NODE_MATCH(n, "comp")) {
		xmlChar *pch = xmlGetProp(n, (const xmlChar *) "name");

		if (pch && value && strcasecmp((char *) pch, value) == 0) {
		    all_comps = FALSE;
		    child = n;
		}
		xmlFree(pch);
	    }
	    else if (NODE_MATCH(n, "allcomp")) {
		all_comps = TRUE;
	    }
	}

	/* if component found and no children ? */
	for (n = child ? child->children : NULL; n != NULL; n = n->next) {
	    if (n->type == XML_ELEMENT_NODE)
		break;
	}

	/* add component with the full content */
	if (child && n == NULL) {
	    all_comps = TRUE;
	    all_props = TRUE;
	}

	if (child == NULL && all_comps != TRUE && c) {
	    icalcomponent *next =
		icalcomponent_get_next_component(parent, ICAL_ANY_COMPONENT);

	    if (c) {
		if (parent != c)
		    icalcomponent_remove_component(parent, c);
		else
		    parent = NULL;
		icalcomponent_free(c);
	    }

	    c = next;
	}
	else {
	    /* prop set or allprop set only == remove props if not included in the list
	     */
	    if (all_props == FALSE || (all_comps == TRUE && all_props == -1)) {
		icalproperty *prop =
			icalcomponent_get_first_property(parent, ICAL_ANY_PROPERTY);

		for ( ; prop != NULL; ) {
		    const char *name = icalproperty_kind_to_string(icalproperty_isa(prop));
		    int f = FALSE;

		    FOR_CHILD(n, node) {
			if (NODE_NOT_CALDAV(n)) {
			    ;
			}
			else if (NODE_MATCH(n, "prop")) {
			    xmlChar *pch = xmlGetProp(n, (const xmlChar *) "name");

			    if (pch && name && strcasecmp((char *) pch, name) == 0) {
				f = TRUE;
				break;
			    }
			    xmlFree(pch);
			}
		    }

		    if (f == FALSE) {
			icalproperty *next =
				icalcomponent_get_next_property(parent, ICAL_ANY_PROPERTY);

			icalcomponent_remove_property(parent, prop);
			icalproperty_free(prop);
			prop = next;
		    }
		    else {
			xmlChar *pch = xmlGetProp(n, (const xmlChar *) "novalue");

			if (pch && strcasecmp((char *) pch, "yes") == 0) {
			    icalvalue *v = icalvalue_new_from_string(icalproperty_isa(prop), "");

			    icalproperty_set_value(prop, v);
			}
			xmlFree(pch);

			prop = icalcomponent_get_next_property(parent, ICAL_ANY_PROPERTY);
		    }
		}
	    }
	    if (c == NULL)
		break;

	    /* look at children ? */
	    if (all_comps == FALSE || all_props == FALSE) {
		icalcomponent *cc;

		do {
		    cc = icalcomponent_get_first_component(c, ICAL_ANY_COMPONENT);

		    show_requested_comps(c, cc, child);

		    cc = icalcomponent_get_next_component(c, ICAL_ANY_COMPONENT);
		} while (cc) ;
	    }
	    c = icalcomponent_get_next_component(parent, ICAL_ANY_COMPONENT);
	}
    } while (c) ;

    return parent;
}

/** remove not requested freebusy properties */
static void show_limited_freebusy(icalcomponent **list, int count,
                                  icaltimetype start, icaltimetype end)
{
    icalcomponent *c;
    icaltime_span basespan, limit = get_limit_span(start, end);
    int i;

    for (i = 0; i < count; i++) {
	icalproperty *prop;

	c = list[i];
	if (icalcomponent_isa(c) != ICAL_VFREEBUSY_COMPONENT)
	    continue;

	prop = icalcomponent_get_first_property(c, ICAL_FREEBUSY_PROPERTY);

	for ( ; prop != NULL; ) {
	    struct icalperiodtype per = icalproperty_get_freebusy(prop);

	    if (!icaltime_is_null_time(per.end))
		basespan = span_new(per.start, per.end, TRUE);
	    else
		basespan = span_new(per.start,
				icaltime_add(per.start, per.duration), TRUE);

	    if (icaltime_span_overlaps(&basespan, &limit) == FALSE) {
		icalproperty *next =
			icalcomponent_get_next_property(c, ICAL_FREEBUSY_PROPERTY);

		icalcomponent_remove_property(c, prop);
		icalproperty_free(prop);
		prop = next;
	    }
	    else {
		prop = icalcomponent_get_next_property(c, ICAL_FREEBUSY_PROPERTY);
	    }
	}
    }
}

/** limit recurrence events */
static void show_limited_recurrence(const icaltimezone *tz,
                                    icalcomponent **list,
                                    int count, icaltimetype start,
                                    icaltimetype end)
{
    icaltime_span limit = get_limit_span(start, end);
    int i;

    for (i = 0; i < count; i++) {
	switch (icalcomponent_isa(list[i])) {
	case ICAL_VTODO_COMPONENT:
	case ICAL_VJOURNAL_COMPONENT:
	case ICAL_VEVENT_COMPONENT:
	    {
		int f = FALSE;

		component_foreach_recurrence(list[i], tz, &limit,
					     overlap_callback, &f);
		if (f == FALSE) {
		    icalcomponent *parent = icalcomponent_get_parent(list[i]);

		    icalcomponent_remove_component(parent, list[i]);
		    icalcomponent_free(list[i]);
		    list[i] = NULL;
		}
	    }
	    break;

	default:
	    break;
	}
    }
}

/** expand cb structure */
typedef struct _expand_recur
{
    icalcomponent *vcalendar, *c;
} expand_recur_t;

/** recurrence event actual expansion and time changes to UTC */
static void expand_callback(icalcomponent *comp, int first,
                            struct icaltime_span *span,
                            struct icaltime_span *limit, void *data)
{
    expand_recur_t *e = data;
    icalcomponent *n;
    icalproperty *prop;
    const char *uid = NULL;
    icaltimetype recur = { 0 }, start = { 0 };

    if (icaltime_span_overlaps(span, limit) == FALSE)
	return;

    n = icalcomponent_new(icalcomponent_isa (e->c));

    /** most of the times seem to be in UTC format
     *  so keep them as-is */
    for (prop = icalcomponent_get_first_property(e->c, ICAL_ANY_PROPERTY);
	 prop != NULL;
	 prop = icalcomponent_get_next_property(e->c, ICAL_ANY_PROPERTY)) {

	switch (icalproperty_isa(prop)) {
	case ICAL_UID_PROPERTY:
	    uid = icalproperty_get_uid(prop);

	    icalcomponent_add_property(n, icalproperty_new_clone(prop));
	    break;

	case ICAL_DUE_PROPERTY:
	    {
		icaltimetype t = icalproperty_get_due(prop);

		if (!icaltime_is_utc(t) && !icaltime_is_date(t))
		    t = icaltime_convert_to_zone(t, icaltimezone_get_utc_timezone());
		icalcomponent_add_property(n, icalproperty_new_due(t));
	    }
	    break;

	case ICAL_RECURRENCEID_PROPERTY:
	    /* this skips timezone ....
	     * recur = icalproperty_get_recurrenceid(prop);
	     */
	    recur = get_datetime(e->c, prop);

	    if (!icaltime_is_utc(recur))
		recur = icaltime_convert_to_zone(recur,
						 icaltimezone_get_utc_timezone());
	    break;

	case ICAL_DTSTART_PROPERTY:
	    {
		start = icaltime_from_timet_with_zone(span->start, 0, NULL);

		if (!icaltime_is_utc(start))
		    start = icaltime_convert_to_zone(start,
						     icaltimezone_get_utc_timezone());
		icalcomponent_add_property(n, icalproperty_new_dtstart(start));
	    }
	    break;

	case ICAL_DTEND_PROPERTY:
	    {
		icaltimetype t = icaltime_from_timet_with_zone(span->end, 0, NULL);

		icalcomponent_add_property(n, icalproperty_new_dtend(t));
	    }
	    break;

	    /* remove these */
	case ICAL_RRULE_PROPERTY:
	    break;

	default:
	    icalcomponent_add_property(n, icalproperty_new_clone(prop));
	    break;
	}
    }

    if (!icaltime_is_null_time(recur) && uid) {
	icalcomponent *c =
	    icalcomponent_get_first_component(e->vcalendar,
						icalcomponent_isa(e->c));

	for ( ; c != NULL;
	     c = icalcomponent_get_next_component(e->vcalendar,
						  icalcomponent_isa(e->c))) {
	    icaltimetype ret;
	    const char *pcsz;

	    prop = icalcomponent_get_first_property(c, ICAL_DTSTART_PROPERTY);
	    ret = icalvalue_get_datetime(icalproperty_get_value(prop));

	    prop = icalcomponent_get_first_property(c, ICAL_UID_PROPERTY);
	    pcsz = icalproperty_get_uid(prop);

	    if (uid && pcsz && strcmp(pcsz, uid) == 0 &&
		icaltime_compare(ret, recur) == 0) {

		icalcomponent_remove_component(icalcomponent_get_parent(c), c);
		icalcomponent_free(c);
		break;
	    }
	}
    }

    if (first == FALSE || !icaltime_is_null_time(recur))
	icalcomponent_add_property (n,
		icalproperty_new_recurrenceid(first == FALSE ? start : recur));

    icalcomponent_add_component(e->vcalendar, n);
}

/** expand recurrence events */
static icalcomponent *show_expanded_recurrence(icalcomponent *root,
                                               const icaltimezone *tz,
                                               icalcomponent **list, int count,
                                               icaltimetype start,
                                               icaltimetype end)
{
    icaltime_span limit = get_limit_span(start, end);
    int i;
    expand_recur_t e[1] = { { 0 } };
    icalproperty *prop;
    icalcomponent *vcalendar = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    for (prop = icalcomponent_get_first_property(root, ICAL_ANY_PROPERTY);
	 prop != NULL;
	 prop = icalcomponent_get_next_property(root, ICAL_ANY_PROPERTY))
	icalcomponent_add_property(vcalendar, icalproperty_new_clone(prop));

    e->vcalendar = vcalendar;

    for (i = 0; i < count; i++) {
	switch (icalcomponent_isa(list[i])) {
	case ICAL_VTODO_COMPONENT:
	case ICAL_VJOURNAL_COMPONENT:
	case ICAL_VEVENT_COMPONENT:
	    {
		e->c = list[i];

		component_foreach_recurrence(list[i], tz, &limit, expand_callback, e);
	    }
	    break;

	default:
	    break;
	}
    }

    return vcalendar;
}

/** dump component contents after filtering */
static char *caldav_ical_dump_query(icalcomponent **proot,
                                    const icaltimezone *tz,
                                    icalcomponent **list, int count,
                                    xmlNodePtr caldata)
{
    xmlNodePtr child = NULL, comp = NULL;
    icaltimetype start = { 0 }, end = { 0 };
    char *pch = NULL;
    report_enum_t report = REPORT_ALL;
    icalcomponent *p = NULL, *root = *proot;
    int i, found = count;

    for (i = 0; i < found; i++) {
	icalcomponent_kind ev = icalcomponent_isa(list[i]);

	/* check this, are there any other possible components ? */
	if (ev == ICAL_VEVENT_COMPONENT ||
	    ev == ICAL_VTODO_COMPONENT ||
	    ev == ICAL_VJOURNAL_COMPONENT) {

	    icalproperty *prop =
		icalcomponent_get_first_property(list[i], ICAL_DTSTART_PROPERTY);

	    if (prop != NULL) {
		icalcomponent *c;
		icalparameter *param =
			icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);

		if (param != NULL) {
		    const char *tzid = icalparameter_get_tzid(param);

		    for (c = icalcomponent_get_parent(list[i]);
			 c != NULL; c = icalcomponent_get_parent(c)) {

			icalcomponent *vtz =
				icalcomponent_get_first_component(c, ICAL_VTIMEZONE_COMPONENT);

			for ( ; vtz != NULL;
			     vtz = icalcomponent_get_next_component(c, ICAL_VTIMEZONE_COMPONENT)) {

			    const char *tzid1;
			    icalproperty *prop1 = 
				icalcomponent_get_first_property(vtz, ICAL_TZID_PROPERTY);

			    if (prop1 != NULL) {
				tzid1 = icalproperty_get_tzid(prop1);

				if (tzid1 && tzid && strcmp(tzid, tzid1) == 0) {
				    icalcomponent *dl;

				    add_component_to_list(vtz, &list, &count);

				    for (dl = icalcomponent_get_first_component(vtz, ICAL_ANY_COMPONENT);
					 dl != NULL;
					 dl = icalcomponent_get_next_component(vtz, ICAL_ANY_COMPONENT))
					add_component_to_list(dl, &list, &count);
				    break;
				}
			    }
			}
		    }
		}
	    }
	}
	/* add parent components to the list array */
	for (p = icalcomponent_get_parent(list[i]);
		p != NULL; p = icalcomponent_get_parent(p))
	    add_component_to_list(p, &list, &count);
    }
    root = remove_comps_not_found(root, root, list, count);

    FOR_CHILD(child, caldata) {
	if (NODE_NOT_CALDAV(child)) {
	    ;
	}
	else if (NODE_MATCH(child, "limit-recurrence-set")) {
	    caldav_ical_timerange(child, &start, &end);

	    report = REPORT_LIMIT_RECUR;
	}
	else if (NODE_MATCH(child, "limit-freebusy-set")) {
	    caldav_ical_timerange(child, &start, &end);

	    report = REPORT_LIMIT_FREEBUSY;
	}
	else if (NODE_MATCH(child, "expand")) {
	    caldav_ical_timerange(child, &start, &end);

	    report = REPORT_EXPAND;
	}
	else if (NODE_MATCH(child, "comp")) {
	    comp = child->parent;
	}
    }

    if (comp)
	root = show_requested_comps(root, root, comp);

    p = NULL;
    switch (report) {
    case REPORT_ALL:
	break;

    case REPORT_LIMIT_RECUR:
	show_limited_recurrence(tz, list, count, start, end);
	break;

    case REPORT_LIMIT_FREEBUSY:
	show_limited_freebusy(list, count, start, end);
	break;

    case REPORT_EXPAND:
	p = show_expanded_recurrence(root, tz, list, count, start, end);
	break;
    }

    if (p) {
	pch = icalcomponent_as_ical_string_r(p);
	icalcomponent_free(p);
    }
    else {
	pch = root ? icalcomponent_as_ical_string_r(root) : NULL;
    }

    free(list);

    *proot = root;

    return pch;
}

/** local search structure */
struct caldav_search_s
{
    xmlNodePtr caldata, filter;
    const icaltimezone *tz;
    icalcomponent *root;
    icalcomponent **plist;
    int count;
};

/**
 * check if search criterias fit in this resource
 * allows request handler to omit this resource
 */
int caldav_ical_search(const char *file, const icaltimezone *tz,
                       xmlNodePtr caldata, xmlNodePtr filter,
                       caldav_search_t **pp)
{
    caldav_search_t *p = *pp = calloc(1, sizeof(*p));

    p->tz = tz;
    p->root = parse_text(file);
    p->caldata = caldata;
    p->filter = filter;

    if (filter == NULL)
	return 1;

    caldav_ical_recursion(p->root, tz, filter, &p->plist, &p->count);

    return p->count;
}

/** return ical stuff as string for all requested reports */
char *caldav_ical_dump(caldav_search_t *p)
{
    char *pch;

    if (p == NULL)
	return NULL;

    /* dump full content */
    if (p->filter == NULL) {
	pch = p->root ? icalcomponent_as_ical_string_r(p->root) : NULL;
    }
    else {
	/* dump selected components only */
	pch = caldav_ical_dump_query(&p->root, p->tz, p->plist, p->count,
				     p->caldata);
	p->plist = NULL;
    }

    return pch;
}

/** free resources for search/query */
int caldav_ical_free(caldav_search_t *p)
{
    if (p == NULL)
	return -1;

    if (p->root) {
	icalcomponent_free(p->root);
	p->root = NULL;
    }
    free(p);

    return 0;
}
