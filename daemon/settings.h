/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
*     Copyright 2015 Couchbase, Inc
*
*   Licensed under the Apache License, Version 2.0 (the "License");
*   you may not use this file except in compliance with the License.
*   You may obtain a copy of the License at
*
*       http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*   See the License for the specific language governing permissions and
*   limitations under the License.
*/

#pragma once

#include <memcached/engine.h>

#ifdef __cplusplus
extern "C" {
#endif

struct interface {
    const char *host;
    struct {
        const char *key;
        const char *cert;
    } ssl;
    int maxconn;
    int backlog;
    in_port_t port;
    bool ipv6;
    bool ipv4;
    bool tcp_nodelay;
};

/* pair of shared object name and config for an extension to be loaded. */
struct extension_settings {
    const char* soname;
    const char* config;
};

/* When adding a setting, be sure to update process_stat_settings */
/**
 * Globally accessible settings as derived from the commandline / JSON config
 * file.
 */
struct settings {

    /*************************************************************************
     * These settings are directly exposed via the config file / cmd line
     * options:
     */
    const char *admin;      /* admin username */
    bool disable_admin;     /* true if admin disabled. */
    int num_threads;        /* number of worker (without dispatcher) libevent
                               threads to run */
    struct interface *interfaces; /* array of interface settings we are
                                     listening on */
    int num_interfaces;     /* size of {interfaces} */
    /* array of extensions and their settings to be loaded. */
    struct extension_settings *pending_extensions;
    int num_pending_extensions; /* size of above array. */
    const char *engine_module; /* engine shared object */
    const char *engine_config; /* engine configuration string */
    const char *audit_file; /* The file containing audit configuration */
    const char *rbac_file; /* The file containing RBAC information */
    bool require_sasl;      /* require SASL auth */
    int verbose;            /* level of versosity to log at. */
    int bio_drain_buffer_sz; /* size of the SSL bio buffers */
    bool datatype;          /* is datatype support enabled? */
    const char *root; /* The root directory of the installation */

    /* Maximum number of io events to process based on the priority of the
       connection */
    int reqs_per_event_high_priority;
    int reqs_per_event_med_priority;
    int reqs_per_event_low_priority;
    int default_reqs_per_event;

    /* flags for each of the above config options, indicating if they were
     * specified in a parsed config file.
     */
    struct {
        bool admin;
        bool threads;
        bool interfaces;
        bool extensions;
        bool engine;
        bool audit;
        bool rbac;
        bool require_sasl;
        bool reqs_per_event_high_priority;
        bool reqs_per_event_med_priority;
        bool reqs_per_event_low_priority;
        bool default_reqs_per_event;
        bool verbose;
        bool bio_drain_buffer_sz;
        bool datatype;
        bool root;
    } has;
    /*************************************************************************
     * These settings are not exposed to the user, and are either derived from
     * the above, or not directly configurable:
     */
    int maxconns;           /* Total number of permitted connections. Derived
                               from sum of all individual interfaces */
    bool sasl;              /* SASL on/off */
    int topkeys;            /* Number of top keys to track */

    /* Handle of the v0 and v1 engine callbacks. */
    union {
        ENGINE_HANDLE *v0;
        ENGINE_HANDLE_V1 *v1;
    } engine;

    /* linked lists of all loaded extensions */
    struct {
        EXTENSION_DAEMON_DESCRIPTOR *daemons;
        EXTENSION_LOGGER_DESCRIPTOR *logger;
        EXTENSION_BINARY_PROTOCOL_DESCRIPTOR *binary;
    } extensions;

    const char *config;      /* The configuration specified by -C (json) */
};

#ifdef __cplusplus
} // extern "C"
#endif