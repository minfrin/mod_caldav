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

#if 0
LoadModule caldav_module modules/mod_caldav.so

<Location /caldav>
    SetHandler caldav_handler
    MinDateTime
    MaxDateTime
    MaxInstances 10
    MaxAttendeesPerInstance  1000
</Location>
#endif

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "http_core.h"

#include "apr_strings.h"

#include "mod_dav.h"

#include "unixd.h"

#include <libxml/tree.h>
#include <libical/ical.h>

#undef PACKAGE_NAME
#undef PACKAGE_VERSION
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME

#include "config.h"

#include "mod_caldav.h"
#include "caldav_liveprops.h"
#include "mod_dav_acl.h"
#include "caldav_ical.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>

module AP_MODULE_DECLARE_DATA caldav_module;

#define CALDAV_FILTER "caldav_filter_in"

/* MKCALENDAR METHOD index */
static int iM_MKCALENDAR;

/* server configuration data */
typedef struct _caldav_server_cfg {

} caldav_server_cfg;

/* directory configuration data */
typedef struct _caldav_dir_cfg {
    char *min_date_time,
         *max_date_time,
         *max_instances,
         *max_attendees_per_instance;
    int etag_response;
    const dav_provider *provider;
} caldav_dir_cfg;

typedef struct _caldav_freebusy {
    const icaltimezone *tz;
    icaltimetype start;
    icaltimetype end;
    icalcomponent *freebusy;
} caldav_freebusy_t;

/* server config create */
static void *caldav_create_server_config(apr_pool_t *p, server_rec *s)
{
    int cb = sizeof(caldav_server_cfg);

    return apr_pcalloc(p, cb ? cb : 1);
}

static void *caldav_create_dir_config(apr_pool_t *p, char *dirspec)
{
    caldav_dir_cfg *conf = apr_pcalloc(p, sizeof(*conf));

    conf->provider = dav_lookup_provider(DAV_DEFAULT_PROVIDER);

    return conf;
}

#define STR_CONF_FUNC(x, val)                                                         \
                                                                                \
/* directive */                                                                        \
static const char *caldav_##x(cmd_parms *cmd, void *mconfig, const char *pch)        \
{                                                                                \
    caldav_dir_cfg *conf = mconfig;                                                \
                                                                                \
    conf->x = (char*)apr_psprintf(cmd->pool, "%s", pch ? pch : val);                \
                                                                                \
    return NULL;                                                                \
}

STR_CONF_FUNC(min_date_time, "20060101T000000Z")
STR_CONF_FUNC(max_date_time, "20060101T000000Z")
STR_CONF_FUNC(max_instances, "10000")
STR_CONF_FUNC(max_attendees_per_instance, "100")

#define DIRECTIVE(n, f, d)                                        \
    AP_INIT_TAKE1(                                                \
        n,                /* directive name */                        \
        caldav_##f,        /* config action routine */                \
        NULL,                /* argument to include in call */        \
        OR_OPTIONS,        /* where available */                        \
        d                /* directive description */                \
      ),

/*
 * Command handler for the DAVETagResponse directive, which is FLAG.
 */
static const char *etag_response(cmd_parms *cmd, void *config, int arg)
{
    caldav_dir_cfg *conf = config;

    conf->etag_response = arg;

    return NULL;
}

/* cmd callbacks */
static const command_rec caldav_cmds[] =
{
    DIRECTIVE("MinDateTime",  min_date_time, "Minumum datetime")
    DIRECTIVE("MaxDateTime",  max_date_time, "Maximum datetime")
    DIRECTIVE("MaxInstances", max_instances, "Maximum instances")
    DIRECTIVE("MaxAttendeesPerInstance", max_attendees_per_instance,
                "Maximum attendees per instance")

    /* per directory/location, or per server */
    AP_INIT_FLAG("CalQueryETagResponse", etag_response, NULL,
                 OR_OPTIONS, "response with ETag for calendar-query"),
    { NULL }
};

/** store resource type for a calendar collection */
static int caldav_store_resource_type(request_rec *r,
                                      const dav_resource *resource)
{
    dav_db *db;
    dav_namespace_map *map = NULL;
    dav_prop_name restype[1] = { { NS_DAV, "resourcetype" } };
    apr_xml_elem el_child[1] = { { 0 } };
    apr_text text = { 0 };
    apr_array_header_t *ns;
    const dav_provider *provider = dav_lookup_provider(DAV_DEFAULT_PROVIDER);
    const dav_hooks_propdb *db_hooks = provider ? provider->propdb : NULL;

    if (!provider || !resource || !db_hooks)
        return -1;

    ns = apr_array_make(resource->pool, 3, sizeof(const char *));
    *(const char**) apr_array_push (ns) = NS_DAV;
    *(const char**) apr_array_push (ns) = NS_CALDAV;

    el_child->name = "resourcetype";
    el_child->ns = 1;
    el_child->first_cdata.first = &text;
    text.text = "calendar";

    db_hooks->open(resource->pool, resource, 0, &db);
    if (db) {
        db_hooks->map_namespaces(db, ns, &map);
        db_hooks->store(db, restype, el_child, map);
        db_hooks->close(db);
        return 0;
    }

    return -1;
}

/* generic read for props */
static dav_error *caldav_read_allowed(request_rec *r,
                                      const dav_resource *resource)
{
    const dav_prop_name privs[] = { { NS_DAV, "read" } };

    return dav_acl_check(r, resource, ARRAY(privs));
}

/* allprops */
static dav_error *caldav_prop_allowed(request_rec *r,
                                      const dav_resource *resource,
                                      const dav_prop_name *name,
                                      dav_prop_insert what)
{
    const dav_prop_name privs[] = { { NS_DAV, "read" } };

    return dav_acl_check(r, resource, ARRAY(privs));
}

static dav_acl_provider *caldav_acl_hooks(void)
{
    static dav_acl_provider h =
    {
        .acl_check_read = caldav_read_allowed,
        .acl_check_prop = caldav_prop_allowed
    };

    return &h;
}

/* freebusy privilege */
static dav_error *caldav_freebusy_allowed(request_rec *r,
                                          const dav_resource *resource)
{
    const dav_prop_name privs[] = { { NS_DAV, "read" },
                                    { NS_CALDAV, "read-free-busy" } };

    return dav_acl_check(r, resource, ARRAY(privs));
}

/** send props of a single file */
static void caldav_send_props(apr_bucket_brigade *bb, request_rec *r,
                              request_rec *rf, dav_resource *resource,
                              apr_pool_t *subpool, caldav_search_t *p,
                              xmlNode *prop)
{
    dav_response response = { 0 };
    dav_propdb *propdb = NULL;

    rf->user = r->user;
    rf->per_dir_config = r->per_dir_config;
    rf->server = r->server;
    rf->method_number = r->method_number;

    response.href = rf->uri;

    if (prop) {
        apr_xml_doc *adoc = dav_acl_get_prop_doc(r, prop);

        dav_open_propdb(rf, NULL, resource, 1, adoc->namespaces, &propdb);

        /* store these for dav_get_props callbacks */
        resource->ctx = p;
        resource->acls = caldav_acl_hooks();
        response.propresult = dav_get_props(propdb, adoc);
    }
    apr_pool_clear(subpool);
    dav_send_one_response(&response, bb, r, subpool);

    if (propdb)
        dav_close_propdb(propdb);
}

/** return default timezone */
static const icaltimezone *caldav_timezone(request_rec *r,
                                           const dav_resource *resource,
                                           caldav_dir_cfg *conf)
{
    dav_prop_name prop = { NS_CALDAV, "calendar-timezone" };
    const char *time_zone = NULL;
    icalcomponent *c;

    if (resource->collection == FALSE) {
        char *pr = strrchr(r->filename, '/');

        if (pr && *pr) {
            dav_resource *parent = NULL;

            *pr = 0;
            if (conf->provider->repos->
                        get_parent_resource(resource, &parent) == NULL)
                time_zone = dav_acl_get_prop(r, parent, conf->provider, &prop);
            *pr = '/';
        }
    }
    else {
        time_zone = dav_acl_get_prop(r, resource, conf->provider, &prop);
    }

    c = time_zone ? icalparser_parse_string(time_zone) : NULL;

    if (c) {
        const char *tzid;
        icalproperty *prop =
                icalcomponent_get_first_property(c, ICAL_TZID_PROPERTY);
        /* Get the TZID property of the first VTIMEZONE. */
        if (prop == NULL)
            return NULL;

        tzid = icalproperty_get_tzid(prop);
        if (tzid == NULL)
            return NULL;

        return icalcomponent_get_timezone(c, tzid);
    }

    return NULL;
}

/** init multistatus response */
static void caldav_init_multistatus(apr_bucket_brigade **bb, request_rec *r)
{
    if (bb == NULL || *bb)
        return;

    *bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    dav_begin_multistatus(*bb, r, HTTP_MULTI_STATUS, NULL);
}

/** send calendar props from several files */
static void caldav_send_calendar_props(const char *subdir, int depth,
                                       int depth_current,
                                       apr_bucket_brigade **bb, request_rec *r,
                                       caldav_dir_cfg *conf, apr_pool_t *subpool,
                                       xmlNode *prop, void *p)
{
    struct stat st;
    apr_status_t rc;
    const char *directory = subdir ? subdir : r->filename;
    struct dirent entry[offsetof(struct dirent, d_name) +
                        pathconf(directory, _PC_NAME_MAX) + 1];
    DIR *dp;

    depth_current++;
    if (depth_current > depth)
        return;

    for (dp = opendir(directory); dp; ) {
        char *file;
        struct dirent *res = NULL;

        if (readdir_r(dp, entry, &res) != 0 || res == NULL)
            break;

        /* no current/parent dir or hidden file == .* */
        if (entry->d_name[0] == '.')
            continue;
        file = apr_pstrcat(subpool, directory, entry->d_name, NULL);
        stat(file, &st);

        if ((st.st_mode & S_IFDIR) == S_IFDIR) {
            if (depth_current >= depth)
                break;

            file = apr_pstrcat(subpool, file, "/", NULL);
            caldav_send_calendar_props(file, depth, depth_current, bb, r,
                                        conf, subpool, prop, p);
        }
        else if ((st.st_mode & S_IFREG) == S_IFREG) {
            dav_resource *resource = NULL;
            xmlNode *caldata = NULL, *child = NULL;
            caldav_search_t *p = NULL;
            request_rec *rf = apr_pcalloc(r->pool, sizeof(*rf));

            rf->filename = file;
            apr_pool_create(&rf->pool, NULL);
            rf->uri = apr_pstrcat(rf->pool, r->uri, file + strlen(r->filename), NULL);
            rc = apr_stat(&rf->finfo, rf->filename, APR_FINFO_MIN, rf->pool);

            if (rc == APR_SUCCESS && conf->provider->repos->
                        get_resource(rf, NULL, NULL, 0, &resource) == NULL) {

                FOR_CHILD(caldata, prop) {
                    if (NODE_NOT_CALDAV(caldata))
                        ;
                    else if (NODE_MATCH(caldata, "calendar-data"))
                        break;
                }
                child = prop ? prop->parent : NULL;
                FOR_CHILD(child, child) {
                    if (NODE_NOT_CALDAV(child))
                        ;
                    else if (NODE_MATCH(child, "filter"))
                        break;
                }

                if (child &&
                        caldav_ical_search(rf->filename,
                                           caldav_timezone(rf, resource, conf),
                                           caldata, child->children, &p)) {
                    caldav_init_multistatus(bb, r);
                    caldav_send_props(*bb, r, rf, resource, subpool, p, prop);
                }
                caldav_ical_free(p);
            }

            apr_pool_destroy(rf->pool);
        }
    }
    closedir(dp);
}

const char *caldav_ctag(request_rec *r)
{
    char *ctag = NULL;

    dav_acl_last_mtime(NULL, r, r->pool, 0);

    if (r->mtime) {
        ctag = ap_make_etag(r, 0);

        if (ctag && ctag[0] == '"')
            ctag++;

        if (ctag) {
            int c = strlen(ctag);

            if (c && ctag[c - 1] == '"')
                ctag[c - 1] = 0;
        }
    }

    return ctag;
}

/** dump multistatus response */
static int caldav_dump(void (*dump_props)(const char *subdir, int depth,
                                          int depth_current,
                                          apr_bucket_brigade **bb,
                                          request_rec *r, caldav_dir_cfg *conf,
                                          apr_pool_t *subpool, xmlNode *prop,
                                          void *p),
                       dav_resource *resource, request_rec *r,
                       caldav_dir_cfg *conf, xmlNode *node,
                       int depth, void *p)
{
    apr_pool_t *subpool;
    apr_bucket_brigade *bb = NULL;

    apr_pool_create(&subpool, r->pool);

    if (dump_props == caldav_send_calendar_props && conf->etag_response) {
        const char *if_none_match;

        dav_acl_last_mtime(NULL, r, subpool, 0);

        if_none_match = apr_table_get(r->headers_in, "If-None-Match");

        if (if_none_match != NULL) {
            int cb = strlen(if_none_match);
            const char *etag = r->mtime ? ap_make_etag(r, 0) : NULL;

            if ((strcmp(if_none_match, "*") == 0 && etag != NULL) ||
                (if_none_match[0] == '"' && cb > 2 &&
                        if_none_match[cb - 1] == '"' &&
                        etag && strcmp(if_none_match, etag) == 0)) {
                r->status_line = ap_get_status_line(r->status = 304);
                apr_pool_destroy(subpool);
                return 0;
            }
        }
        ap_set_etag(r);
    }

    dump_props(NULL, depth, 0, &bb, r, conf, subpool, node, p);

    if (bb) {
        dav_finish_multistatus(r, bb);
    }
    else {
        if (dump_props == caldav_send_calendar_props)
            apr_table_unset(r->headers_out, "ETag");

        r->status_line = ap_get_status_line(r->status = 404);
    }
    apr_pool_destroy(subpool);

    return 0;
}

/** check free busy info from a collection */
static void caldav_send_free_busy(const char *subdir, int depth,
                                  int depth_current,
                                  apr_bucket_brigade **bb, request_rec *r,
                                  caldav_dir_cfg *conf,
                                  apr_pool_t *subpool,
                                  xmlNode *prop, void *p)
{
    struct stat st;
    apr_status_t rc;
    const char *directory = subdir ? subdir : r->filename;
    DIR *dp;
    caldav_freebusy_t *freebusy = p;
    struct dirent entry[offsetof(struct dirent, d_name) +
                        pathconf(directory, _PC_NAME_MAX) + 1];

    depth_current++;
    if (depth_current > depth)
        return;

    for (dp = opendir(directory); dp; ) {
        char *file;
        struct dirent *res = NULL;

        if (readdir_r(dp, entry, &res) != 0 || res == NULL)
            break;

        /* no current/parent dir or hidden file == .* */
        if (entry->d_name[0] == '.')
            continue;

        file = apr_pstrcat(subpool, directory, entry->d_name, NULL);
        stat(file, &st);

        if ((st.st_mode & S_IFDIR) == S_IFDIR) {
            if (depth_current >= depth)
                break;

            file = apr_pstrcat(subpool, file, "/", NULL);
            caldav_send_free_busy(file, depth, depth_current, bb, r, conf,
                                  subpool, prop, p);
        }
        else if ((st.st_mode & S_IFREG) == S_IFREG) {
            dav_resource *resource = NULL;
            request_rec *rf = apr_pcalloc(r->pool, sizeof(*rf));

            rf->filename = file;
            apr_pool_create(&rf->pool, NULL);
            rf->uri = apr_pstrcat(rf->pool, r->uri,
                                  file + strlen(r->filename), NULL);
            rc = apr_stat(&rf->finfo, rf->filename, APR_FINFO_MIN, rf->pool);

            if (rc == APR_SUCCESS && conf->provider->repos->
                        get_resource(rf, NULL, NULL, 0, &resource) == NULL &&
                        caldav_freebusy_allowed(r, resource) == NULL)
                caldav_ical_freebusy(rf->filename, freebusy->tz,
                                        freebusy->start, freebusy->end,
                                        freebusy->freebusy);

            apr_pool_destroy(rf->pool);
        }
    }
    closedir(dp);
}

/** reply for multiget */
static void caldav_send_multiget(const char *subdir, int depth,
                                 int depth_current, apr_bucket_brigade **bb,
                                 request_rec *r, caldav_dir_cfg *conf,
                                 apr_pool_t *subpool, xmlNode *prop, void *p)
{
    apr_status_t rc;
    xmlNode *node = NULL;

    if (prop == NULL) {
        dav_handle_err(r, dav_new_error(r->pool, HTTP_NOT_FOUND, 0, APR_SUCCESS,
                                        "Property <prop> not given"), NULL);
        return;
    }
    if (depth_current >= depth)
        return;

    FOR_CHILD(node, prop->parent) {
        if (NODE_NOT_DAV(node)) {
            ;
        }
        else if (NODE_MATCH(node, "href")) {
            caldav_search_t *p = NULL;
            dav_resource *resource = NULL;
            request_rec *rf;
            dav_lookup_result lookup = { 0 };
            apr_uri_t uri = { 0 };
            xmlChar *pch = xmlNodeGetContent(node);

            if (pch == NULL)
                continue;

            rf = apr_pcalloc(r->pool, sizeof(*rf));

            apr_pool_create(&rf->pool, NULL);
            apr_uri_parse(rf->pool, (char *) pch, &uri);

            lookup = dav_lookup_uri((char *) pch, r, uri.scheme != NULL);

            if (lookup.rnew && lookup.rnew->status == HTTP_OK) {
                rf->filename = lookup.rnew->filename;
                rf->uri = lookup.rnew->uri;

                rc = apr_stat(&rf->finfo, rf->filename, APR_FINFO_MIN, rf->pool);

                if (rc == APR_SUCCESS &&
                        conf->provider->repos->get_resource(rf, NULL, NULL, 0,
                                                            &resource) == NULL) {
                    if (caldav_ical_search(rf->filename, NULL, NULL, NULL, &p)) {
                        caldav_init_multistatus(bb, r);
                        caldav_send_props(*bb, r, rf, resource, subpool, p, prop);
                    }
                    caldav_ical_free(p);
                }
            }
            if (lookup.rnew)
                ap_destroy_sub_req(lookup.rnew);

            apr_pool_destroy(rf->pool);
            xmlFree(pch);
        }
    }
}

static int dav_process_ctx_list(void (*func)(dav_prop_ctx *ctx),
                                apr_array_header_t *ctx_list, int stop_on_error,
                                int reverse)
{
    int i = ctx_list->nelts;
    dav_prop_ctx *ctx = (dav_prop_ctx *) ctx_list->elts;

    if (reverse)
        ctx += i;

    while (i--) {
        if (reverse)
            --ctx;

        func (ctx);
        if (stop_on_error && DAV_PROP_CTX_HAS_ERR(*ctx))
             return 1;

        if (!reverse)
             ++ctx;
    }

    return 0;
}

static void caldav_log_err(request_rec *r, dav_error *err, int level)
{
    dav_error *errscan;

    /* Log the errors */
    /* ### should have a directive to log the first or all */
    for (errscan = err; errscan != NULL; errscan = errscan->prev) {
        if (errscan->desc == NULL)
            continue;

        ap_log_rerror(APLOG_MARK, level, errscan->aprerr, r, "%s [%d, #%d]",
            errscan->desc, errscan->status, errscan->error_id);
    }
}

static void caldav_prop_log_errors(dav_prop_ctx *ctx)
{
    caldav_log_err(ctx->r, ctx->err, APLOG_ERR);
}

/** MKCALENDAR */
static int caldav_mkcalendar(caldav_dir_cfg *conf, request_rec *r)
{
    dav_resource *resource = NULL;
    dav_error *err = NULL;
    const dav_prop_name privs[] = {
        { NS_DAV, "write" },
        { NS_DAV, "bind" } };
    dav_response *multi_status;
    int resource_state, result;
    apr_xml_doc *doc;
    dav_resource *parent = NULL;

    if (conf->provider == NULL)
        return dav_handle_err(r, dav_new_error (r->pool, HTTP_FORBIDDEN, 0, APR_SUCCESS,
                              "Directory path not configured, you need some "
                              "caldav directives !"), NULL);

    if ((err = conf->provider->repos->get_resource(r, NULL, NULL, 0, &resource)))
        return dav_handle_err(r, err, NULL);

    if ((err = conf->provider->repos->get_parent_resource(resource, &parent)))
        return dav_handle_err(r, err, NULL);

    if ((err = dav_acl_check(r, parent, ARRAY (privs))))
        return dav_handle_err(r, err, NULL);

    if (resource->exists) {
        err = dav_new_error(r->pool, HTTP_FORBIDDEN, 0, APR_SUCCESS, "Collection exists already");
        err->tagname = "resource-must-be-null";
        return dav_handle_err(r, err, NULL);
    }
    resource_state = dav_get_resource_state(r, resource);

    err = dav_validate_request(r, resource, 0, NULL, &multi_status,
                                resource_state == DAV_RESOURCE_NULL ?
                                    DAV_VALIDATE_PARENT : DAV_VALIDATE_RESOURCE,
                                NULL);
    if (err != NULL)
        /* ### add a higher-level description? */
        return dav_handle_err(r, err, multi_status);

    /* resource->collection = 1; */
    if ((err = resource->hooks->create_collection(resource)))
        return dav_handle_err (r, err, NULL);

    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
        ;
    }
    else if (doc) {
        dav_auto_version_info av_info;
        dav_propdb *propdb;
        dav_prop_ctx *ctx;
        apr_xml_elem *child;
        int failure = 0;
        apr_array_header_t *ctx_list;
        apr_text *propstat_text;

        /* make sure the resource can be modified (if versioning repository) */
        if ((err = dav_auto_checkout(r, resource, 0 /* not parent_only */,
                                     &av_info)) != NULL) {
            /* ### add a higher-level description? */
            return dav_handle_err(r, err, NULL);
        }
        if ((err = dav_open_propdb(r, NULL, resource, 0, doc->namespaces,
                                   &propdb)) != NULL) {
            /* undo any auto-checkout */
            dav_auto_checkin(r, resource, 1 /*undo*/, 0 /*unlock*/, &av_info);

            err = dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
                        apr_psprintf(r->pool,
                                     "Could not open the property database for %s.",
                                     ap_escape_html(r->pool, r->uri)), err);
            return dav_handle_err(r, err, NULL);
        }
        /* ### what to do about closing the propdb on server failure? */

        /* ### validate "live" properties */

        /* set up an array to hold property operation contexts */
        ctx_list = apr_array_make(r->pool, 10, sizeof(dav_prop_ctx));

        /* do a first pass to ensure that all "remove" properties exist */
        for (child = doc->root->first_child; child; child = child->next) {
            apr_xml_elem *prop_group;
            apr_xml_elem *one_prop;

            /* Ignore children that are not set/remove */
            if (child->ns != APR_XML_NS_DAV_ID ||
                        strcmp(child->name, "set") != 0)
                continue;

            /* make sure that a "prop" child exists for set/remove */
            if ((prop_group = dav_find_child(child, "prop")) == NULL) {
                dav_close_propdb(propdb);

                /* undo any auto-checkout */
                dav_auto_checkin(r, resource, 1 /*undo*/, 0 /*unlock*/, &av_info);

                /* This supplies additional information for the default message. */
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "A \"prop\" element is missing inside "
                              "the propertyupdate command.");
                return HTTP_BAD_REQUEST;
            }

            for (one_prop = prop_group->first_child; one_prop;
                        one_prop = one_prop->next) {

                ctx = (dav_prop_ctx *) apr_array_push(ctx_list);
                ctx->propdb = propdb;
                ctx->operation = DAV_PROP_OP_SET;
                ctx->prop = one_prop;

                ctx->r = r;        /* for later use by dav_prop_log_errors() */

                dav_prop_validate(ctx);

                if (DAV_PROP_CTX_HAS_ERR(*ctx))
                    failure = 1;
            }
        }
        /* ### should test that we found at least one set/remove */

        /* execute all of the operations */
        if (!failure && dav_process_ctx_list(dav_prop_exec, ctx_list, 1, 0))
            failure = 1;

        /* generate a failure/success response */
        if (failure) {
            dav_process_ctx_list(dav_prop_rollback, ctx_list, 0, 1);
            propstat_text = dav_failed_proppatch(r->pool, ctx_list);
        }
        else {
            dav_process_ctx_list(dav_prop_commit, ctx_list, 0, 0);
            /* propstat_text = dav_success_proppatch(r->pool, ctx_list); */
        }
        /* make sure this gets closed! */
        dav_close_propdb(propdb);

        /* complete any auto-versioning */
        dav_auto_checkin(r, resource, failure, 0 /*unlock*/, &av_info);

        /* log any errors that occurred */
        dav_process_ctx_list(caldav_prop_log_errors, ctx_list, 0, 0);

        if (failure) {
            dav_response resp = { 0 };

            resp.href = resource->uri;

            /* ### should probably use something new to pass along this text... */
            resp.propresult.propstats = propstat_text;

            dav_send_multistatus(r, HTTP_MULTI_STATUS, &resp, doc->namespaces);
            return DONE;
        }
    }
    if ((resource->acls = dav_get_acl_providers("acl")))
        resource->acls->acl_post_processing(r, resource, 1);

    caldav_store_resource_type(r, resource);

    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

    r->status_line = ap_get_status_line(r->status = 201);

    return DONE;
}

static void free_busy(caldav_dir_cfg *conf, request_rec *r,
                      dav_resource *resource, int depth, xmlNode *node)
{
    icaltimetype start = { 0 }, end = { 0 };
    xmlNode *child = NULL;
    caldav_freebusy_t fb[1] = { { 0 } };
    icalcomponent *vcalendar;
    icalcomponent *vfreebusy;
    char *pch;

    FOR_CHILD(child, node) {
        if (NODE_NOT_CALDAV(child)) {
            ;
        }
        else if (NODE_MATCH(child, "time-range"))  {
            caldav_ical_timerange(child, &start, &end);
            break;
        }
    }
    vcalendar = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    icalcomponent_add_property(vcalendar, icalproperty_new_version("2.0"));

    icalcomponent_add_property(vcalendar,
                        icalproperty_new_prodid("-//Nokia//Test server//EN"));

    vfreebusy = icalcomponent_new(ICAL_VFREEBUSY_COMPONENT);
    icalcomponent_add_property(vfreebusy, icalproperty_new_dtstamp(start));
    icalcomponent_add_property(vfreebusy, icalproperty_new_dtstart(start));
    icalcomponent_add_property(vfreebusy, icalproperty_new_dtend(end));

    icalcomponent_add_component(vcalendar, vfreebusy);

    fb->freebusy = vfreebusy;
    fb->start = start;
    fb->end = end;
    fb->tz = caldav_timezone(r, resource, conf);

    /* not a multistatus reponse, but multifile... */
    caldav_send_free_busy(NULL, depth, 0, NULL, r, conf, r->pool, node, fb);

    ap_set_content_type(r, "text/calendar");
    ap_rprintf(r, "%s", pch = icalcomponent_as_ical_string_r(vcalendar));
    free(pch);

    r->status_line = ap_get_status_line(r->status = 200);
    icalcomponent_free(vcalendar);
}

/* calendar REPORTs */
static int caldav_report(caldav_dir_cfg *conf, request_rec *r)
{
    dav_resource *resource = NULL;
    dav_error *err = NULL;
    xmlDoc *doc = NULL;
    ap_filter_t *inf;
    dav_buffer *buffer = NULL;
    int rc = 0;
    xmlNode *node;
    int depth;

    /* acl checks on individual reports */
    if (conf->provider == NULL)
        return dav_handle_err(r,
                dav_new_error(r->pool, HTTP_FORBIDDEN, 0, APR_SUCCESS,
                              "Directory path not configured, you need some "
                              "caldav directives !"), NULL);

    if ((err = conf->provider->repos->get_resource(r, NULL, NULL, 0, &resource)))
        return dav_handle_err(r, err, NULL);

    /* read the body content from the buffer if it was consumed already by
     * another client */
    for (inf = r->input_filters; inf; inf = inf->next) {
        if (inf->frec && inf->frec->name &&
                !strcmp(inf->frec->name, CALDAV_FILTER)) {
            dav_acl_input_filter_t *f = inf->ctx;

            if (f && f->r == r) {
                inf->ctx = NULL;
                buffer = &f->buffer;
                ap_remove_input_filter(inf);
                break;
            }
        }
    }
    if (buffer == NULL)   /* internal error */
        return DECLINED;

    if (buffer->cur_len == 0)
        rc = dav_acl_read_body(r, buffer);

    if (rc < 0 || !(doc = xmlReadMemory(buffer->buf, buffer->cur_len,
                                        NULL, NULL, XML_PARSE_NOWARNING)))
        return DECLINED;

    for (node = doc->children; node; node = node->next) {
        int query;

        if (NODE_NOT_CALDAV(node)) {
            if (node->type == XML_ELEMENT_NODE) {
                xmlFreeDoc(doc);
                return DECLINED;
            }
        }
        else if ((query = NODE_MATCH(node, "calendar-query")) ||
                     (NODE_MATCH(node, "calendar-multiget"))) {
            xmlNode *child = NULL;

            if ((depth = dav_get_depth(r, 0)) < 0)
                goto error;

            FOR_CHILD(child, node) {
                if (NODE_NOT_DAV(child))
                    ;
                else if (NODE_MATCH(child, "prop"))
                    break;
            }

            caldav_dump(query ? caldav_send_calendar_props : caldav_send_multiget,
                        resource, r, conf, child, depth, NULL);
            break;
        }
        else if (NODE_MATCH(node, "free-busy-query")) {
            if ((depth = dav_get_depth(r, 0)) < 0)
                goto error;

            free_busy(conf, r, resource, depth, node);
            break;
        }
        else if (node->type == XML_ELEMENT_NODE) {
            xmlFreeDoc(doc);
            return DECLINED;
        }
    }
    if (node == NULL) {
        xmlFreeDoc(doc);
        return DECLINED;
    }

    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");
    xmlFreeDoc(doc);
    return OK;

error:
    xmlFreeDoc(doc);
    err = dav_new_error(r->pool, HTTP_BAD_REQUEST, 0, APR_SUCCESS,
                        "Depth-header value incorrect");
    return dav_handle_err(r, err, NULL);
}

/* caldav handler callback */
static int caldav_handler(request_rec *r)
{
#if 0
    caldav_server_cfg *sconf = (caldav_server_cfg *)
        ap_get_module_config(r->server->module_config, &caldav_module);
#endif
    caldav_dir_cfg *conf = ap_get_module_config(r->per_dir_config,
                                                &caldav_module);

    if (conf == NULL || conf->provider == NULL)
        return DECLINED;

    if (r->method_number == iM_MKCALENDAR)
        return caldav_mkcalendar(conf, r);
    else if (r->method_number == M_REPORT)
        return caldav_report(conf, r);
    else
        return DECLINED;
}

static void caldav_initialize_child(apr_pool_t *p, server_rec *s)
{
}

/** module init */
static int caldav_initialize_module(apr_pool_t *p, apr_pool_t *plog,
                                    apr_pool_t *ptemp, server_rec *s)
{
    void *data;
    const char *key = "caldav_start";

    /**
     * initialize_acl_module() will be called twice, and if it's a DSO
     * then all static data from the first call will be lost. Only
     * set up our static data on the second call.
     */
    apr_pool_userdata_get(&data, key, s->process->pool);
    if (data == NULL) {
        apr_pool_userdata_set((const void *) 1, key,
                              apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    /* Register CalDAV methods */
    iM_MKCALENDAR = ap_method_register(p, "MKCALENDAR");

    return OK;
}

/** dav header callback in options request */
static dav_error *caldav_options_dav_header(request_rec *r,
                                            const dav_resource *resource,
                                            apr_text_header *phdr)
{
    apr_text_append(r->pool, phdr, "calendar-access");

    return NULL;
}

/** method callback for options request */
static dav_error *caldav_options_dav_method(request_rec *r,
                                            const dav_resource *resource,
                                            apr_text_header *phdr)
{
    apr_text_append(r->pool, phdr, "REPORT");
    apr_text_append(r->pool, phdr, "MKCALENDAR");

    return NULL;
}

static
#if APACHE_PATCH
dav_hooks_options
#else
dav_options_provider
#endif
options =
{
    caldav_options_dav_header,
    caldav_options_dav_method,
    NULL
};

/** reponse for calendar resource type */
static int caldav_get_resource_type(const dav_resource *resource,
                                    const char **name, const char **uri)
{
    request_rec *r = resource->hooks->get_request_rec(resource);
    caldav_dir_cfg *conf = ap_get_module_config(r->per_dir_config,
                                                &caldav_module);
    dav_prop_name prop = { "DAV:", "resourcetype" };
    const char *pch = dav_acl_get_prop(r, resource, conf->provider, &prop);

    if (pch && strstr(pch, "calendar")) {
        *name = "calendar";
        *uri = NS_CALDAV;
        return 0;
    }
    *name = *uri = NULL;
    return -1;
}

static
#if APACHE_PATCH
dav_hooks_resource
#else
dav_resource_type_provider
#endif
res_hooks =
{
    caldav_get_resource_type
};

static void caldav_add_input_filter(request_rec *r)
{
    if (r->method_number == M_REPORT) {
        dav_acl_input_filter_t *f = apr_pcalloc(r->pool, sizeof(*f));

        f->r = r;
        ap_add_input_filter(CALDAV_FILTER, f, r, r->connection);
    }
}

/* initialize hooks */
static void caldav_register_hooks(apr_pool_t *p)
{
    /**
     * static const char * const dav_acl[] = { "mod_dav_acl.c", NULL };
     * ap_hook_handler(caldav_handler, NULL, dav_acl, APR_HOOK_MIDDLE);
     */
    ap_hook_insert_filter(caldav_add_input_filter, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_input_filter(CALDAV_FILTER, dav_acl_input_filter, NULL, AP_FTYPE_RESOURCE);

    ap_hook_post_config(caldav_initialize_module, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(caldav_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(caldav_initialize_child, NULL, NULL, APR_HOOK_MIDDLE);

    /* live property handling */
    dav_hook_gather_propsets(caldav_gather_propsets, NULL, NULL, APR_HOOK_MIDDLE);
    dav_hook_find_liveprop(caldav_find_liveprop, NULL, NULL, APR_HOOK_MIDDLE);
    caldav_register_props(p);

#if APACHE_PATCH
    dav_options_register_hooks(p, "caldav", &options);

    dav_resource_register_hooks(p, "caldav", &res_hooks);
#else
    dav_options_provider_register(p, "caldav", &options);

    dav_resource_type_provider_register(p, "caldav", &res_hooks);
#endif
}

module AP_MODULE_DECLARE_DATA caldav_module =
{
    STANDARD20_MODULE_STUFF,
    caldav_create_dir_config,                /* per-directory config creator */
    NULL,                                /* dir config merger */
    caldav_create_server_config,        /* server config creator */
    NULL,                                /* server config merger */
    caldav_cmds,                        /* command table */
    caldav_register_hooks,                /* set up other request processing hooks */
};

        int depth;
