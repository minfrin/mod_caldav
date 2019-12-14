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
/*
 * caldav_liveprops.c: mod_caldav live property provider functions
 *
 */

#include <sys/types.h>

#include <httpd.h>
#include <libxml/tree.h>

#include <mod_dav.h>
#include "caldav.h"

#include "mod_dav_acl.h"

#include <libical/ical.h>
#include "mod_caldav.h"
#include "apr_strings.h"
#include "caldav_ical.h"

#define NS_CTAG "http://calendarserver.org/ns/"

/*
** The namespace URIs that we use. This list and the enumeration must
** stay in sync.
*/
static const char * const caldav_namespace_uris[] =
{
    NS_CALDAV,
    NS_CTAG,
    NULL        /* sentinel */
};

enum {
    CALDAV_NAMESPACE_URI_NO = 0,  /* the CALDAV: namespace URI ref number */
    CALDAV_NAMESPACE_CTAG_NO      /* the CTAG: namespace URI ref number */
};

#define CALDAV_RO_PROP(name, enum_name) \
        { CALDAV_NAMESPACE_URI_NO, name, CALDAV_PROPID_##enum_name, 0 }
#define CALDAV_RW_PROP(name, enum_name) \
        { CALDAV_NAMESPACE_URI_NO, name, CALDAV_PROPID_##enum_name, 1 }

enum {
    CALDAV_PROPID_calendar_description = 1,
    CALDAV_PROPID_calendar_timezone,
    CALDAV_PROPID_supported_calendar_component_set,
    CALDAV_PROPID_supported_calendar_data,
    CALDAV_PROPID_max_resource_size,
    CALDAV_PROPID_min_date_time,
    CALDAV_PROPID_max_date_time,
    CALDAV_PROPID_max_instances,
    CALDAV_PROPID_max_attendees_per_instance,
    CALDAV_PROPID_calendar_data,
    CALDAV_PROPID_calendar_home_set,
    CALDAV_PROPID_getctag
};

static const dav_liveprop_spec caldav_props[] =
{
    CALDAV_RO_PROP("supported-calendar-component-set", supported_calendar_component_set),
    CALDAV_RO_PROP("supported-calendar-data", supported_calendar_data),
    CALDAV_RO_PROP("max-resource-size", max_resource_size),
    CALDAV_RO_PROP("min-date-time", min_date_time),
    CALDAV_RO_PROP("max-date-time", max_date_time),
    CALDAV_RO_PROP("max-instances", max_instances),
    CALDAV_RO_PROP("max-attendees-per-instance", max_attendees_per_instance),
    CALDAV_RW_PROP("calendar-description", calendar_description),
    CALDAV_RW_PROP("calendar-timezone", calendar_timezone),
    CALDAV_RO_PROP("calendar-data", calendar_data),
    CALDAV_RW_PROP("calendar-home-set", calendar_home_set),

    { CALDAV_NAMESPACE_CTAG_NO, "getctag", CALDAV_PROPID_getctag, 0 },

    { 0 } /* sentinel */
};

const dav_hooks_liveprop caldav_hooks_liveprop;

static const dav_liveprop_group caldav_liveprop_group =
{
    caldav_props,
    caldav_namespace_uris,
    &caldav_hooks_liveprop
};


static dav_prop_insert caldav_insert_prop(const dav_resource *resource,
                                                int propid,
                                                dav_prop_insert what,
                                                apr_text_header *phdr)
{
    const char *value = NULL;
    const char *s = NULL;
    apr_pool_t *p = resource->pool;
    const dav_liveprop_spec *info;
    int global_ns;
    char *fval = NULL;

    if (!resource->exists)
        return DAV_PROP_INSERT_NOTDEF;

    /* ### we may want to respond to DAV_PROPID_resourcetype for PRIVATE
       ### resources. need to think on "proper" interaction with mod_dav */

    switch (propid) {
    case CALDAV_PROPID_getctag:
        {
            request_rec *r = resource->hooks->get_request_rec(resource);

            value = caldav_ctag(r);
            if (value == NULL)
                return DAV_PROP_INSERT_NOTDEF;
        }
        break;

    case CALDAV_PROPID_calendar_data:
        {
            request_rec *r = resource->hooks->get_request_rec(resource);
            caldav_search_t *p;

            if (r->method_number != M_REPORT)
                return DAV_PROP_INSERT_NOTDEF;

            p = resource->ctx;
            value = fval = caldav_ical_dump(p);
            if (value == NULL)
                return DAV_PROP_INSERT_NOTDEF;
            break;
        }

    default:
        /* ### what the heck was this property? */
        return DAV_PROP_INSERT_NOTDEF;
    }

    /* assert: value != NULL */

    /* get the information and global NS index for the property */
    global_ns = dav_get_liveprop_info(propid, &caldav_liveprop_group, &info);

    /* assert: info != NULL && info->name != NULL */

    if (what == DAV_PROP_INSERT_VALUE)
        s = apr_psprintf(p, "<lp%d:%s>%s</lp%d:%s>" DEBUG_CR,
                         global_ns, info->name, value, global_ns, info->name);
    else if (what == DAV_PROP_INSERT_NAME)
        s = apr_psprintf(p, "<lp%d:%s/>" DEBUG_CR, global_ns, info->name);
    else
        /* assert: what == DAV_PROP_INSERT_SUPPORTED */
        s = apr_psprintf(p, "<D:supported-live-property D:name=\"%s\" "
                            "D:namespace=\"%s\"/>" DEBUG_CR,
                            info->name, caldav_namespace_uris[info->ns]);

    apr_text_append(p, phdr, s);

    free(fval);
    /* we inserted whatever was asked for */
    return what;
}

static int caldav_is_writable (const dav_resource *resource, int propid)
{
    const dav_liveprop_spec *info;

    dav_get_liveprop_info(propid, &caldav_liveprop_group, &info);

    return info->is_writable;
}

static dav_error *caldav_patch_validate(const dav_resource *resource,
                                        const apr_xml_elem *elem,
                                        int operation, void **context,
                                        int *defer_to_dead)
{
    /* NOTE: this function will not be called unless/until we have
       modifiable (writable) live properties. */
    dav_elem_private *priv = elem->priv;

    switch (priv->propid) {
    case CALDAV_PROPID_calendar_description:
        *defer_to_dead = TRUE;
        break;

    case CALDAV_PROPID_calendar_timezone:
        /* actually a dead property, but defined as alive to have
         * this callback for proppatch
         */
        *defer_to_dead = TRUE;
        break;

    case CALDAV_PROPID_calendar_home_set:
        if (!dav_acl_is_resource_principal(resource)) {
            return dav_new_error(resource->pool, HTTP_CONFLICT, 0, APR_SUCCESS,
                                 "The resource URI is not a principal");
        }
        *defer_to_dead = TRUE;
        break;

    default:
        break;
    }
    return NULL;
}

static dav_error *caldav_patch_exec(const dav_resource *resource,
                                        const apr_xml_elem *elem,
                                        int operation, void *context,
                                        dav_liveprop_rollback **rollback_ctx)
{
    /* NOTE: this function will not be called unless/until we have
       modifiable (writable) live properties. */
    return NULL;
}

static void caldav_patch_commit(const dav_resource *resource,
                                int operation, void *context,
                                dav_liveprop_rollback *rollback_ctx)
{
    /* NOTE: this function will not be called unless/until we have
       modifiable (writable) live properties. */
}

static dav_error *caldav_patch_rollback(const dav_resource *resource,
                                        int operation, void *context,
                                        dav_liveprop_rollback *rollback_ctx)
{
    /* NOTE: this function will not be called unless/until we have
       modifiable (writable) live properties. */
    return NULL;
}

const dav_hooks_liveprop caldav_hooks_liveprop = {
    caldav_insert_prop,
    caldav_is_writable,
    caldav_namespace_uris,
    caldav_patch_validate,
    caldav_patch_exec,
    caldav_patch_commit,
    caldav_patch_rollback,
};

void caldav_gather_propsets(apr_array_header_t *uris)
{
}

int caldav_find_liveprop(const dav_resource *resource,
                                const char *ns_uri, const char *name,
                                const dav_hooks_liveprop **hooks)
{
    /* don't try to find any liveprops if this isn't "our" resource
        if (resource->hooks != &caldav_hooks_repos)
           return 0;
     */
    return dav_do_find_liveprop(ns_uri, name, &caldav_liveprop_group, hooks);
}

void caldav_register_props(apr_pool_t *p)
{
    /* register the namespace URIs */
    dav_register_liveprop_group(p, &caldav_liveprop_group);
}

