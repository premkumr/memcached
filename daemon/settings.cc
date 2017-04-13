/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015 Couchbase, Inc.
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

#include "config.h"

#include <platform/dirutils.h>
#include <platform/strerror.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <system_error>

#include "log_macros.h"
#include "settings.h"
#include "ssl_utils.h"

// the global entry of the settings object
Settings settings;


/**
 * Initialize all members to "null" to preserve backwards
 * compatibility with the previous versions.
 */
Settings::Settings()
    : num_threads(0),
      require_sasl(false),
      bio_drain_buffer_sz(0),
      datatype_json(false),
      datatype_snappy(false),
      reqs_per_event_high_priority(0),
      reqs_per_event_med_priority(0),
      reqs_per_event_low_priority(0),
      default_reqs_per_event(00),
      max_packet_size(0),
      require_init(false),
      topkeys_size(0),
      stdin_listen(false),
      exit_on_connection_close(false),
      maxconns(0) {

    verbose.store(0);
    connection_idle_time.reset();
    dedupe_nmvb_maps.store(false);
    xattr_enabled.store(false);
    privilege_debug.store(false);

    memset(&has, 0, sizeof(has));
    memset(&extensions, 0, sizeof(extensions));
}

Settings::Settings(const unique_cJSON_ptr& json)
    : Settings() {
    reconfigure(json);
}

/**
 * Handle deprecated tags in the settings by simply ignoring them
 */
static void ignore_entry(Settings&, cJSON*) {
}

enum class FileError {
    Missing,
    Empty,
    Invalid
};

static void throw_file_exception(const std::string &key,
                                 const std::string& filename,
                                 FileError reason,
                                 const std::string& extra_reason = std::string()) {
    std::string message("'" + key + "': '" + filename + "'");
    if (reason == FileError::Missing) {
        throw std::system_error(
                std::make_error_code(std::errc::no_such_file_or_directory),
                message);
    } else if (reason == FileError::Empty) {
        throw std::invalid_argument(message + " is empty ");
    } else if (reason == FileError::Invalid) {
        std::string extra;
        if (!extra_reason.empty()) {
            extra = " (" + extra_reason + ")";
        }
        throw std::invalid_argument(message + " is badly formatted: " +
                                    extra_reason);
    } else {
        throw std::runtime_error(message);
    }
}

static void throw_missing_file_exception(const std::string &key,
                                         const cJSON *obj) {
    throw_file_exception(key,
                         obj->valuestring == nullptr ? "null" : obj->valuestring,
                         FileError::Missing);
}

static void throw_missing_file_exception(const std::string& key,
                                         const std::string& filename) {
    throw_file_exception(key, filename, FileError::Missing);
}

/**
 * Handle the "rbac_file" tag in the settings
 *
 *  The value must be a string that points to a file that must exist
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_rbac_file(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_String) {
        throw std::invalid_argument("\"rbac_file\" must be a string");
    }

    if (!cb::io::isFile(obj->valuestring)) {
        throw_missing_file_exception("rbac_file", obj);
    }

    s.setRbacFile(obj->valuestring);
}

/**
 * Handle the "privilege_debug" tag in the settings
 *
 *  The value must be a boolean value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_privilege_debug(Settings& s, cJSON* obj) {
    if (obj->type == cJSON_True) {
        s.setPrivilegeDebug(true);
    } else if (obj->type == cJSON_False) {
        s.setPrivilegeDebug(false);
    } else {
        throw std::invalid_argument(
            "\"privilege_debug\" must be a boolean value");
    }
}

/**
 * Handle the "audit_file" tag in the settings
 *
 *  The value must be a string that points to a file that must exist
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_audit_file(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_String) {
        throw std::invalid_argument("\"audit_file\" must be a string");
    }

    if (!cb::io::isFile(obj->valuestring)) {
        throw_missing_file_exception("audit_file", obj);
    }

    s.setAuditFile(obj->valuestring);
}

static void handle_error_maps_dir(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_String) {
        throw std::invalid_argument("\"error_maps_dir\" must be a string");
    }
    s.setErrorMapsDir(obj->valuestring);
}

/**
 * Handle the "threads" tag in the settings
 *
 *  The value must be an integer value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_threads(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_Number) {
        throw std::invalid_argument("\"threads\" must be an integer");
    }

    s.setNumWorkerThreads(obj->valueint);
}

/**
 * Handle the "require_init" tag in the settings
 *
 *  The value must be a  value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_require_init(Settings& s, cJSON* obj) {
    if (obj->type == cJSON_True) {
        s.setRequireInit(true);
    } else if (obj->type == cJSON_False) {
        s.setRequireInit(false);
    } else {
        throw std::invalid_argument(
            "\"require_init\" must be a boolean value");
    }
}

/**
 * Handle the "require_sasl" tag in the settings
 *
 *  The value must be a  value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_require_sasl(Settings& s, cJSON* obj) {
    if (obj->type == cJSON_True) {
        s.setRequireSasl(true);
    } else if (obj->type == cJSON_False) {
        s.setRequireSasl(false);
    } else {
        throw std::invalid_argument(
            "\"require_sasl\" must be a boolean value");
    }
}

/**
 * Handle "default_reqs_per_event", "reqs_per_event_high_priority",
 * "reqs_per_event_med_priority" and "reqs_per_event_low_priority" tag in
 * the settings
 *
 *  The value must be a integer value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_reqs_event(Settings& s, cJSON* obj) {
    std::string name(obj->string);

    if (obj->type != cJSON_Number) {
        throw std::invalid_argument("\"" + name + "\" must be an integer");
    }

    EventPriority priority;

    if (name == "default_reqs_per_event") {
        priority = EventPriority::Default;
    } else if (name == "reqs_per_event_high_priority") {
        priority = EventPriority::High;
    } else if (name == "reqs_per_event_med_priority") {
        priority = EventPriority::Medium;
    } else if (name == "reqs_per_event_low_priority") {
        priority = EventPriority::Low;
    } else {
        throw std::invalid_argument("Invalid key specified: " + name);
    }
    s.setRequestsPerEventNotification(obj->valueint, priority);
}

/**
 * Handle the "verbosity" tag in the settings
 *
 *  The value must be a numeric value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_verbosity(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_Number) {
        throw std::invalid_argument("\"verbosity\" must be an integer");
    }
    s.setVerbose(obj->valueint);
}

/**
 * Handle the "connection_idle_time" tag in the settings
 *
 *  The value must be a numeric value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_connection_idle_time(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_Number) {
        throw std::invalid_argument(
            "\"connection_idle_time\" must be an integer");
    }
    s.setConnectionIdleTime(obj->valueint);
}

/**
 * Handle the "bio_drain_buffer_sz" tag in the settings
 *
 *  The value must be a numeric value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_bio_drain_buffer_sz(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_Number) {
        throw std::invalid_argument(
            "\"bio_drain_buffer_sz\" must be an integer");
    }
    s.setBioDrainBufferSize(obj->valueint);
}

/**
 * Handle the "datatype_snappy" tag in the settings
 *
 *  The value must be a boolean value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_datatype_json(Settings& s, cJSON* obj) {
    if (obj->type == cJSON_True) {
        s.setDatatypeJsonEnabled(true);
    } else if (obj->type == cJSON_False) {
        s.setDatatypeJsonEnabled(false);
    } else {
        throw std::invalid_argument(
                "\"datatype_json\" must be a boolean value");
    }
}

/**
 * Handle the "datatype_snappy" tag in the settings
 *
 *  The value must be a boolean value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_datatype_snappy(Settings& s, cJSON* obj) {
    if (obj->type == cJSON_True) {
        s.setDatatypeSnappyEnabled(true);
    } else if (obj->type == cJSON_False) {
        s.setDatatypeSnappyEnabled(false);
    } else {
        throw std::invalid_argument(
                "\"datatype_snappy\" must be a boolean value");
    }
}

/**
 * Handle the "root" tag in the settings
 *
 * The value must be a string that points to a directory that must exist
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_root(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_String) {
        throw std::invalid_argument("\"root\" must be a string");
    }

    if (!cb::io::isDirectory(obj->valuestring)) {
        throw_missing_file_exception("root", obj);
    }

    s.setRoot(obj->valuestring);
}

/**
 * Handle the "ssl_cipher_list" tag in the settings
 *
 * The value must be a string
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_ssl_cipher_list(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_String) {
        throw std::invalid_argument("\"ssl_cipher_list\" must be a string");
    }
    s.setSslCipherList(obj->valuestring);
}

/**
 * Handle the "ssl_minimum_protocol" tag in the settings
 *
 * The value must be a string containing one of the following:
 *    tlsv1, tlsv1.1, tlsv1_1, tlsv1.2, tlsv1_2
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_ssl_minimum_protocol(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_String) {
        throw std::invalid_argument(
            "\"ssl_minimum_protocol\" must be a string");
    }

    try {
        decode_ssl_protocol(obj->valuestring);
    } catch (std::exception& e) {
        throw std::invalid_argument(
            "\"ssl_minimum_protocol\"" + std::string(e.what()));
    }
    s.setSslMinimumProtocol(obj->valuestring);
}

/**
 * Handle the "get_max_packet_size" tag in the settings
 *
 *  The value must be a numeric value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_max_packet_size(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_Number) {
        throw std::invalid_argument(
            "\"max_packet_size\" must be an integer");
    }
    s.setMaxPacketSize(obj->valueint * 1024 * 1024);
}

/**
 * Handle the "stdin_listen" tag in the settings
 *
 *  The value must be a boolean value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_stdin_listen(Settings& s, cJSON* obj) {
    if (obj->type == cJSON_True) {
        s.setStdinListen(true);
    } else if (obj->type == cJSON_False) {
        s.setStdinListen(false);
    } else {
        throw std::invalid_argument(
            "\"stdin_listen\" must be a boolean value");
    }
}

/**
 * Handle the "exit_on_connection_close" tag in the settings
 *
 *  The value must be a boolean value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_exit_on_connection_close(Settings& s, cJSON* obj) {
    if (obj->type == cJSON_True) {
        s.setExitOnConnectionClose(true);
    } else if (obj->type == cJSON_False) {
        s.setExitOnConnectionClose(false);
    } else {
        throw std::invalid_argument(
            "\"exit_on_connection_close\" must be a boolean value");
    }
}

/**
 * Handle the "saslauthd_socketpath" tag in the settings
 *
 * The value must be a string
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_saslauthd_socketpath(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_String) {
        throw std::invalid_argument("\"saslauthd_socketpath\" must be a string");
    }

    // We allow non-existing files, because we want to be
    // able to have it start to work if the user end up installing the
    // package after the configuration is set (and it'll just start to
    // work).
    s.setSaslauthdSocketpath(obj->valuestring);
}

/**
 * Handle the "sasl_mechanisms" tag in the settings
 *
 * The value must be a string
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_sasl_mechanisms(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_String) {
        throw std::invalid_argument("\"sasl_mechanisms\" must be a string");
    }
    s.setSaslMechanisms(obj->valuestring);
}

/**
 * Handle the "ssl_sasl_mechanisms" tag in the settings
 *
 * The value must be a string
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_ssl_sasl_mechanisms(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_String) {
        throw std::invalid_argument("\"ssl_sasl_mechanisms\" must be a string");
    }
    s.setSslSaslMechanisms(obj->valuestring);
}


/**
 * Handle the "dedupe_nmvb_maps" tag in the settings
 *
 *  The value must be a boolean value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_dedupe_nmvb_maps(Settings& s, cJSON* obj) {
    if (obj->type == cJSON_True) {
        s.setDedupeNmvbMaps(true);
    } else if (obj->type == cJSON_False) {
        s.setDedupeNmvbMaps(false);
    } else {
        throw std::invalid_argument(
            "\"dedupe_nmvb_maps\" must be a boolean value");
    }
}

/**
 * Handle the "xattr_enabled" tag in the settings
 *
 *  The value must be a boolean value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_xattr_enabled(Settings& s, cJSON* obj) {
    if (obj->type == cJSON_True) {
        s.setXattrEnabled(true);
    } else if (obj->type == cJSON_False) {
        s.setXattrEnabled(false);
    } else {
        throw std::invalid_argument(
            "\"xattr_enabled\" must be a boolean value");
    }
}

/**
 * Handle the "client_cert_auth" tag in the settings
 *
 *  The value must be a string value
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_client_cert_auth(Settings& s, cJSON* obj) {
    if (obj->type == cJSON_Object || obj->type == cJSON_String) {
        ClientCertAuth clientAuth(obj);
        s.setClientCertAuth(clientAuth);
    } else {
        throw std::invalid_argument(
                "\"client_cert_auth\" must be a object or string");
    }
}

/**
 * Handle the "extensions" tag in the settings
 *
 *  The value must be an array
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_extensions(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_Array) {
        throw std::invalid_argument("\"extensions\" must be an array");
    }

    for (auto* child = obj->child; child != nullptr; child = child->next) {
        if (child->type != cJSON_Object) {
            throw std::invalid_argument(
                "Elements in the \"extensions\" array myst be objects");
        }
        extension_settings ext(child);
        s.addPendingExtension(ext);
    }
}

/**
 * Handle the "interfaces" tag in the settings
 *
 *  The value must be an array
 *
 * @param s the settings object to update
 * @param obj the object in the configuration
 */
static void handle_interfaces(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_Array) {
        throw std::invalid_argument("\"interfaces\" must be an array");
    }

    for (auto* child = obj->child; child != nullptr; child = child->next) {
        if (child->type != cJSON_Object) {
            throw std::invalid_argument(
                "Elements in the \"interfaces\" array myst be objects");
        }
        interface ifc(child);
        s.addInterface(ifc);
    }
}

static void handle_breakpad(Settings& s, cJSON* obj) {
    if (obj->type != cJSON_Object) {
        throw std::invalid_argument("\"breakpad\" must be an object");
    }

    BreakpadSettings breakpad(obj);
    s.setBreakpadSettings(breakpad);
}

void Settings::reconfigure(const unique_cJSON_ptr& json) {
    // Nuke the default interface added to the system in settings_init and
    // use the ones in the configuration file.. (this is a bit messy)
    interfaces.clear();

    struct settings_config_tokens {
        /**
         * The key in the configuration
         */
        std::string key;

        /**
         * A callback method used by the Settings object when we're parsing
         * the config attributes.
         *
         * @param settings the Settings object to update
         * @param obj the current object in the configuration we're looking at
         * @throws std::invalid_argument if it something is wrong with the
         *         entry
         */
        void (* handler)(Settings& settings, cJSON* obj);
    };

    std::vector<settings_config_tokens> handlers = {
            {"admin", ignore_entry},
            {"rbac_file", handle_rbac_file},
            {"privilege_debug", handle_privilege_debug},
            {"audit_file", handle_audit_file},
            {"error_maps_dir", handle_error_maps_dir},
            {"threads", handle_threads},
            {"interfaces", handle_interfaces},
            {"extensions", handle_extensions},
            {"require_init", handle_require_init},
            {"require_sasl", handle_require_sasl},
            {"default_reqs_per_event", handle_reqs_event},
            {"reqs_per_event_high_priority", handle_reqs_event},
            {"reqs_per_event_med_priority", handle_reqs_event},
            {"reqs_per_event_low_priority", handle_reqs_event},
            {"verbosity", handle_verbosity},
            {"connection_idle_time", handle_connection_idle_time},
            {"bio_drain_buffer_sz", handle_bio_drain_buffer_sz},
            {"datatype_json", handle_datatype_json},
            {"datatype_snappy", handle_datatype_snappy},
            {"root", handle_root},
            {"ssl_cipher_list", handle_ssl_cipher_list},
            {"ssl_minimum_protocol", handle_ssl_minimum_protocol},
            {"breakpad", handle_breakpad},
            {"max_packet_size", handle_max_packet_size},
            {"stdin_listen", handle_stdin_listen},
            {"exit_on_connection_close", handle_exit_on_connection_close},
            {"saslauthd_socketpath", handle_saslauthd_socketpath},
            {"sasl_mechanisms", handle_sasl_mechanisms},
            {"ssl_sasl_mechanisms", handle_ssl_sasl_mechanisms},
            {"dedupe_nmvb_maps", handle_dedupe_nmvb_maps},
            {"xattr_enabled", handle_xattr_enabled},
            {"client_cert_auth", handle_client_cert_auth}};

    cJSON* obj = json->child;
    while (obj != nullptr) {
        std::string key(obj->string);
        bool found = false;
        for (auto& handler : handlers) {
            if (handler.key == key) {
                handler.handler(*this, obj);
                found = true;
                break;
            }
        }

        if (!found) {
            logit(EXTENSION_LOG_WARNING,
                  "Unknown token \"%s\" in config ignored.\n",
                  obj->string);
        }

        obj = obj->next;
    }
}

static void handle_interface_maxconn(struct interface& ifc, cJSON* obj) {
    if (obj->type != cJSON_Number) {
        throw std::invalid_argument("\"maxconn\" must be a number");
    }

    ifc.maxconn = obj->valueint;
}

static void handle_interface_port(struct interface& ifc, cJSON* obj) {
    if (obj->type != cJSON_Number) {
        throw std::invalid_argument("\"port\" must be a number");
    }

    ifc.port = in_port_t(obj->valueint);
}

static void handle_interface_host(struct interface& ifc, cJSON* obj) {
    if (obj->type != cJSON_String) {
        throw std::invalid_argument("\"host\" must be a string");
    }

    ifc.host.assign(obj->valuestring);
}

static void handle_interface_backlog(struct interface& ifc, cJSON* obj) {
    if (obj->type != cJSON_Number) {
        throw std::invalid_argument("\"backlog\" must be a number");
    }

    ifc.backlog = obj->valueint;
}

static void handle_interface_ipv4(struct interface& ifc, cJSON* obj) {
    if (obj->type == cJSON_True) {
        ifc.ipv4 = true;
    } else if (obj->type == cJSON_False) {
        ifc.ipv4 = false;
    } else {
        throw std::invalid_argument("\"ipv4\" must be a boolean value");
    }
}

static void handle_interface_ipv6(struct interface& ifc, cJSON* obj) {
    if (obj->type == cJSON_True) {
        ifc.ipv6 = true;
    } else if (obj->type == cJSON_False) {
        ifc.ipv6 = false;
    } else {
        throw std::invalid_argument("\"ipv6\" must be a boolean value");
    }
}

static void handle_interface_tcp_nodelay(struct interface& ifc, cJSON* obj) {
    if (obj->type == cJSON_True) {
        ifc.tcp_nodelay = true;
    } else if (obj->type == cJSON_False) {
        ifc.tcp_nodelay = false;
    } else {
        throw std::invalid_argument("\"tcp_nodelay\" must be a boolean value");
    }
}

static void handle_interface_management(struct interface& ifc, cJSON* obj) {
    if (obj->type == cJSON_True) {
        ifc.management = true;
    } else if (obj->type == cJSON_False) {
        ifc.management = false;
    } else {
        throw std::invalid_argument("\"management\" must be a boolean value");
    }
}

static void handle_interface_ssl(struct interface& ifc, cJSON* obj) {
    if (obj->type != cJSON_Object) {
        throw std::invalid_argument("\"ssl\" must be an object");
    }
    auto* key = cJSON_GetObjectItem(obj, "key");
    auto* cert = cJSON_GetObjectItem(obj, "cert");
    if (key == nullptr || cert == nullptr) {
        throw std::invalid_argument(
            "\"ssl\" must contain both \"key\" and \"cert\"");
    }

    if (key->type != cJSON_String) {
        throw std::invalid_argument("\"ssl:key\" must be a key");
    }

    if (!cb::io::isFile(key->valuestring)) {
        throw_missing_file_exception("ssl:key", key);
    }

    if (cert->type != cJSON_String) {
        throw std::invalid_argument("\"ssl:cert\" must be a key");
    }

    if (!cb::io::isFile(cert->valuestring)) {
        throw_missing_file_exception("ssl:cert", cert);
    }

    ifc.ssl.key.assign(key->valuestring);
    ifc.ssl.cert.assign(cert->valuestring);
}

static void handle_interface_protocol(struct interface& ifc, cJSON* obj) {
    if (obj->type != cJSON_String) {
        throw std::invalid_argument("\"protocol\" must be a string");
    }

    std::string protocol(obj->valuestring);

    if (protocol == "memcached") {
        ifc.protocol = Protocol::Memcached;
    } else if (protocol == "greenstack") {
        ifc.protocol = Protocol::Greenstack;
    } else {
        throw std::invalid_argument(
            "\"protocol\" must be \"memcached\" or \"greenstack\"");
    }
}

interface::interface(const cJSON* json)
    : interface() {


    struct interface_config_tokens {
        /**
         * The key in the configuration
         */
        std::string key;

        /**
         * A callback method used by the interface object when we're parsing
         * the config attributes.
         *
         * @param ifc the interface object to update
         * @param obj the current object in the configuration we're looking at
         * @throws std::invalid_argument if it something is wrong with the
         *         entry
         */
        void (* handler)(struct interface& ifc, cJSON* obj);
    };

    std::vector<interface_config_tokens> handlers = {
        {"maxconn",     handle_interface_maxconn},
        {"port",        handle_interface_port},
        {"host",        handle_interface_host},
        {"backlog",     handle_interface_backlog},
        {"ipv4",        handle_interface_ipv4},
        {"ipv6",        handle_interface_ipv6},
        {"tcp_nodelay", handle_interface_tcp_nodelay},
        {"ssl",         handle_interface_ssl},
        {"management",  handle_interface_management},
        {"protocol",    handle_interface_protocol},
    };

    cJSON* obj = json->child;
    while (obj != nullptr) {
        std::string key(obj->string);
        bool found = false;
        for (auto& handler : handlers) {
            if (handler.key == key) {
                handler.handler(*this, obj);
                found = true;
                break;
            }
        }

        if (!found) {
            Settings::logit(EXTENSION_LOG_NOTICE,
                            "Unknown token \"%s\" in config ignored.\n",
                            obj->string);
        }

        obj = obj->next;
    }
}

void Settings::updateSettings(const Settings& other, bool apply) {
    if (other.has.rbac_file) {
        if (other.rbac_file != rbac_file) {
            throw std::invalid_argument("rbac_file can't be changed dynamically");
        }
    }
    if (other.has.threads) {
        if (other.num_threads != num_threads) {
            throw std::invalid_argument("threads can't be changed dynamically");
        }
    }

    if (other.has.audit) {
        if (other.audit_file != audit_file) {
            throw std::invalid_argument("audit can't be changed dynamically");
        }
    }
    if (other.has.require_sasl) {
        if (other.require_sasl != require_sasl) {
            throw std::invalid_argument(
                "require_sasl can't be changed dynamically");
        }
    }
    if (other.has.bio_drain_buffer_sz) {
        if (other.bio_drain_buffer_sz != bio_drain_buffer_sz) {
            throw std::invalid_argument(
                "bio_drain_buffer_sz can't be changed dynamically");
        }
    }
    if (other.has.datatype_json) {
        if (other.datatype_json != datatype_json) {
            throw std::invalid_argument(
                    "datatype_json can't be changed dynamically");
        }
    }
    if (other.has.datatype_snappy) {
        if (other.datatype_snappy != datatype_snappy) {
            throw std::invalid_argument(
                    "datatype_snappy can't be changed dynamically");
        }
    }
    if (other.has.root) {
        if (other.root != root) {
            throw std::invalid_argument("root can't be changed dynamically");
        }
    }
    if (other.has.require_init) {
        if (other.require_init != require_init) {
            throw std::invalid_argument(
                "require_init can't be changed dynamically");
        }
    }
    if (other.has.topkeys_size) {
        if (other.topkeys_size != topkeys_size) {
            throw std::invalid_argument(
                "topkeys_size can't be changed dynamically");
        }
    }
    if (other.has.stdin_listen) {
        if (other.stdin_listen != stdin_listen) {
            throw std::invalid_argument(
                "stdin_listen can't be changed dynamically");
        }
    }
    if (other.has.exit_on_connection_close) {
        if (other.exit_on_connection_close != exit_on_connection_close) {
            throw std::invalid_argument(
                "exit_on_connection_close can't be changed dynamically");
        }
    }
    if (other.has.sasl_mechanisms) {
        if (other.sasl_mechanisms != sasl_mechanisms) {
            throw std::invalid_argument(
                "sasl_mechanisms can't be changed dynamically");
        }
    }
    if (other.has.ssl_sasl_mechanisms) {
        if (other.ssl_sasl_mechanisms != ssl_sasl_mechanisms) {
            throw std::invalid_argument(
                "ssl_sasl_mechanisms can't be changed dynamically");
        }
    }

    if (other.has.interfaces) {
        if (other.interfaces.size() != interfaces.size()) {
            throw std::invalid_argument(
                "interfaces can't be changed dynamically");
        }

        // validate that we haven't changed stuff in the entries
        auto total = interfaces.size();
        for (std::vector<interface>::size_type ii = 0; ii < total; ++ii) {
            const auto& i1 = interfaces[ii];
            const auto& i2 = other.interfaces[ii];

            if (i1.port == 0 || i2.port == 0) {
                // we can't look at dynamic ports...
                continue;
            }

            // the following fields can't change
            if ((i1.host != i2.host) || (i1.port != i2.port) ||
                (i1.ipv4 != i2.ipv4) || (i1.ipv6 != i2.ipv6) ||
                (i1.protocol != i2.protocol) ||
                (i1.management != i2.management)) {
                throw std::invalid_argument(
                    "interfaces can't be changed dynamically");
            }
        }
    }

    if (other.has.extensions) {
        if (other.pending_extensions.size() != pending_extensions.size()) {
            throw std::invalid_argument(
                "extensions can't be changed dynamically");
        }

        // validate that we haven't changed stuff in the entries
        auto total = pending_extensions.size();
        for (std::vector<extension_settings>::size_type ii = 0;
             ii < total; ++ii) {
            const auto& e1 = pending_extensions[ii];
            const auto& e2 = other.pending_extensions[ii];

            if ((e1.config != e2.config) || (e1.soname != e2.soname)) {
                throw std::invalid_argument(
                    "extensions can't be changed dynamically");
            }
        }
    }

    if (other.has.error_maps) {
        if (other.error_maps_dir != error_maps_dir) {
            throw std::invalid_argument(
                    "error_maps_dir can't be changed dynamically");
        }
    }

    // All non-dynamic settings has been validated. If we're not supposed
    // to update anything we can bail out.
    if (!apply) {
        return;
    }


    // Ok, go ahead and update the settings!!
    if (other.has.verbose) {
        if (other.verbose != verbose) {
            logit(EXTENSION_LOG_NOTICE,
                  "Change verbosity level from %u to %u",
                  verbose.load(), other.verbose.load());
            setVerbose(other.verbose.load());
        }
    }

    if (other.has.reqs_per_event_high_priority) {
        if (other.reqs_per_event_high_priority !=
            reqs_per_event_high_priority) {
            logit(EXTENSION_LOG_NOTICE,
                  "Change high priority iterations per event from %u to %u",
                  reqs_per_event_high_priority,
                  other.reqs_per_event_high_priority);
            setRequestsPerEventNotification(other.reqs_per_event_high_priority,
                                            EventPriority::High);
        }
    }
    if (other.has.reqs_per_event_med_priority) {
        if (other.reqs_per_event_med_priority != reqs_per_event_med_priority) {
            logit(EXTENSION_LOG_NOTICE,
                  "Change medium priority iterations per event from %u to %u",
                  reqs_per_event_med_priority,
                  other.reqs_per_event_med_priority);
            setRequestsPerEventNotification(other.reqs_per_event_med_priority,
                                            EventPriority::Medium);
        }
    }
    if (other.has.reqs_per_event_low_priority) {
        if (other.reqs_per_event_low_priority != reqs_per_event_low_priority) {
            logit(EXTENSION_LOG_NOTICE,
                  "Change low priority iterations per event from %u to %u",
                  reqs_per_event_low_priority,
                  other.reqs_per_event_low_priority);
            setRequestsPerEventNotification(other.reqs_per_event_low_priority,
                                            EventPriority::Low);
        }
    }
    if (other.has.default_reqs_per_event) {
        if (other.default_reqs_per_event != default_reqs_per_event) {
            logit(EXTENSION_LOG_NOTICE,
                  "Change default iterations per event from %u to %u",
                  default_reqs_per_event,
                  other.default_reqs_per_event);
            setRequestsPerEventNotification(other.default_reqs_per_event,
                                            EventPriority::Default);
        }
    }
    if (other.has.connection_idle_time) {
        if (other.connection_idle_time != connection_idle_time) {
            logit(EXTENSION_LOG_NOTICE,
                  "Change connection idle time from %u to %u",
                  connection_idle_time.load(),
                  other.connection_idle_time.load());
            setConnectionIdleTime(other.connection_idle_time);
        }
    }
    if (other.has.max_packet_size) {
        if (other.max_packet_size != max_packet_size) {
            logit(EXTENSION_LOG_NOTICE,
                  "Change max packet size from %u to %u",
                  max_packet_size,
                  other.max_packet_size);
            setMaxPacketSize(other.max_packet_size);
        }
    }
    if (other.has.ssl_cipher_list) {
        if (other.ssl_cipher_list != ssl_cipher_list) {
            // this isn't safe!! an other thread could call stats settings
            // which would cause this to crash...
            logit(EXTENSION_LOG_NOTICE,
                  "Change SSL Cipher list from \"%s\" to \"%s\"",
                  ssl_cipher_list.c_str(), other.ssl_cipher_list.c_str());
            setSslCipherList(other.ssl_cipher_list);
        }
    }
    if (other.has.client_cert_auth) {
        if (client_cert_auth != other.client_cert_auth) {
            logit(EXTENSION_LOG_NOTICE,
                  "Change SSL client auth from \"%s\" to \"%s\"",
                  getClientCertAuthStr().c_str(),
                  other.getClientCertAuthStr().c_str());
            setClientCertAuth(other.client_cert_auth);
        }
    }
    if (other.has.ssl_minimum_protocol) {
        if (other.ssl_minimum_protocol != ssl_minimum_protocol) {
            // this isn't safe!! an other thread could call stats settings
            // which would cause this to crash...
            logit(EXTENSION_LOG_NOTICE,
                  "Change SSL minimum protocol from \"%s\" to \"%s\"",
                  ssl_minimum_protocol.c_str(),
                  other.ssl_minimum_protocol.c_str());
            setSslMinimumProtocol(other.ssl_minimum_protocol);
        }
    }
    if (other.has.dedupe_nmvb_maps) {
        if (other.dedupe_nmvb_maps != dedupe_nmvb_maps) {
            logit(EXTENSION_LOG_NOTICE,
                  "%s deduplication of NMVB maps",
                  other.dedupe_nmvb_maps.load() ? "Enable" : "Disable");
            setDedupeNmvbMaps(other.dedupe_nmvb_maps.load());
        }
    }

    if (other.has.xattr_enabled) {
        if (other.xattr_enabled != xattr_enabled) {
            logit(EXTENSION_LOG_NOTICE,
                  "%s xattr",
                  other.xattr_enabled.load() ? "Enable" : "Disable");
            setXattrEnabled(other.xattr_enabled.load());
        }
    }

    if (other.has.interfaces) {
        // validate that we haven't changed stuff in the entries
        auto total = interfaces.size();
        bool changed = false;
        for (std::vector<interface>::size_type ii = 0; ii < total; ++ii) {
            auto& i1 = interfaces[ii];
            const auto& i2 = other.interfaces[ii];

            if (i1.port == 0 || i2.port == 0) {
                // we can't look at dynamic ports...
                continue;
            }

            if (i2.maxconn != i1.maxconn) {
                logit(EXTENSION_LOG_NOTICE,
                      "Change max connections for %s:%u from %u to %u",
                      i1.host.c_str(), i1.port, i1.maxconn, i2.maxconn);
                i1.maxconn = i2.maxconn;
                changed = true;
            }

            if (i2.backlog != i1.backlog) {
                logit(EXTENSION_LOG_NOTICE,
                      "Change backlog for %s:%u from %u to %u",
                      i1.host.c_str(), i1.port, i1.backlog, i2.backlog);
                i1.backlog = i2.backlog;
                changed = true;
            }

            if (i2.tcp_nodelay != i1.tcp_nodelay) {
                logit(EXTENSION_LOG_NOTICE,
                      "%e TCP NODELAY for %s:%u",
                      i2.tcp_nodelay ? "Enable" : "Disable",
                      i1.host.c_str(), i1.port);
                i1.tcp_nodelay = i2.tcp_nodelay;
                changed = true;
            }

            if (i2.ssl.cert != i1.ssl.cert) {
                logit(EXTENSION_LOG_NOTICE,
                      "Change SSL Certificiate for %s:%u from %s to %s",
                      i1.host.c_str(), i1.port, i1.ssl.cert.c_str(),
                      i2.ssl.cert.c_str());
                i1.ssl.cert.assign(i2.ssl.cert);
                changed = true;
            }

            if (i2.ssl.key != i1.ssl.key) {
                logit(EXTENSION_LOG_NOTICE,
                      "Change SSL Key for %s:%u from %s to %s",
                      i1.host.c_str(), i1.port, i1.ssl.key.c_str(),
                      i2.ssl.key.c_str());
                i1.ssl.key.assign(i2.ssl.key);
                changed = true;
            }
        }

        if (changed) {
            notify_changed("interfaces");
        }
    }

    if (other.has.breakpad) {
        bool changed = false;
        auto& b1 = breakpad;
        const auto& b2 = other.breakpad;

        if (b2.isEnabled() != b1.isEnabled()) {
            logit(EXTENSION_LOG_NOTICE,
                  "%e breakpad",
                  b2.isEnabled() ? "Enable" : "Disable");
            b1.setEnabled((b2.isEnabled()));
            changed = true;
        }

        if (b2.getMinidumpDir() != b1.getMinidumpDir()) {
            logit(EXTENSION_LOG_NOTICE,
                  "Change minidump directory from \"%s\" to \"%s\"",
                  b1.getMinidumpDir().c_str(),
                  b2.getMinidumpDir().c_str());
            b1.setMinidumpDir(b2.getMinidumpDir());
            changed = true;
        }

        if (b2.getContent() != b1.getContent()) {
            logit(EXTENSION_LOG_NOTICE,
                  "Change minidump content from %u to %u",
                  b1.getContent(),
                  b2.getContent());
            b1.setContent(b2.getContent());
            changed = true;
        }

        if (changed) {
            notify_changed("breakpad");
        }
    }

    if (other.has.privilege_debug) {
        if (other.privilege_debug != privilege_debug) {
            bool value = other.isPrivilegeDebug();
            logit(EXTENSION_LOG_NOTICE, "%s privilege debug",
                  value ? "Enable" : "Disable");
            setPrivilegeDebug(value);
        }
    }

    if (other.has.saslauthd_socketpath) {
        // @todo fixme
        auto path = other.getSaslauthdSocketpath();
        if (path != saslauthd_socketpath.path) {
            logit(EXTENSION_LOG_NOTICE,
                  "Change saslauthd socket path from \"%s\" to \"%s\"",
                  saslauthd_socketpath.path.c_str(),
                  path.c_str());
            setSaslauthdSocketpath(path);
        }
    }
}

void Settings::logit(EXTENSION_LOG_LEVEL level, const char* fmt, ...) {
    auto logger = settings.extensions.logger;
    if (logger != nullptr) {
        char buffer[1024];

        va_list ap;
        va_start(ap, fmt);
        auto len = vsnprintf(buffer, sizeof(buffer), fmt, ap);
        va_end(ap);
        if (len < 0) {
            return;
        }
        buffer[sizeof(buffer) - 1] = '\0';

        logger->log(level, nullptr, "%s", buffer);
    }
}

/**
 * Loads a single error map
 * @param filename The location of the error map
 * @param[out] contents The JSON-encoded contents of the error map
 * @return The version of the error map
 */
static size_t parseErrorMap(const std::string& filename,
                            std::string& contents) {
    const std::string errkey(
            "parseErrorMap: error_maps_dir (" + filename + ")");
    if (!cb::io::isFile(filename)) {
        throw_missing_file_exception(errkey, filename);
    }

    std::ifstream ifs(filename);
    if (ifs.good()) {
        // Read into buffer
        contents.assign(std::istreambuf_iterator<char>{ifs},
                        std::istreambuf_iterator<char>());
        if (contents.empty()) {
            throw_file_exception(errkey, filename, FileError::Empty);
        }
    } else if (ifs.fail()) {
        // TODO: make this into std::system_error
        throw std::runtime_error(errkey + ": " + "Couldn't read");
    }

    unique_cJSON_ptr json(cJSON_Parse(contents.c_str()));
    if (json.get() == nullptr) {
        throw_file_exception(errkey, filename, FileError::Invalid,
                             "Invalid JSON");
    }

    if (json->type != cJSON_Object) {
        throw_file_exception(errkey, filename, FileError::Invalid,
                             "Top-level contents must be objects");
    }
    // Find the 'version' field
    const cJSON *verobj = cJSON_GetObjectItem(json.get(), "version");
    if (verobj == nullptr) {
        throw_file_exception(errkey, filename, FileError::Invalid,
                             "Cannot find 'version' field");
    }
    if (verobj->type != cJSON_Number) {
        throw_file_exception(errkey, filename, FileError::Invalid,
                             "'version' must be numeric");
    }

    static const size_t max_version = 200;
    size_t version = verobj->valueint;

    if (version > max_version) {
        throw_file_exception(errkey, filename, FileError::Invalid,
                             "'version' too big. Maximum supported is " +
                             std::to_string(max_version));
    }

    return version;
}

void Settings::loadErrorMaps(const std::string& dir) {
    static const std::string errkey("Settings::loadErrorMaps");
    if (!cb::io::isDirectory(dir)) {
        throw_missing_file_exception(errkey, dir);
    }

    size_t max_version = 1;
    static const std::string prefix("error_map");
    static const std::string suffix(".json");

    for (auto const& filename : cb::io::findFilesWithPrefix(dir, prefix)) {
        // Ensure the filename matches "error_map*.json", so we ignore editor
        // generated files or "hidden" files.
        if (filename.size() < suffix.size()) {
            continue;
        }
        if (!std::equal(suffix.rbegin(), suffix.rend(), filename.rbegin())) {
            continue;
        }

        std::string contents;
        size_t version = parseErrorMap(filename, contents);
        error_maps.resize(std::max(error_maps.size(), version + 1));
        error_maps[version] = contents;
        max_version = std::max(max_version, version);
    }

    // Ensure we have at least one error map.
    if (error_maps.empty()) {
        throw std::invalid_argument(errkey +": No valid files found in " + dir);
    }

    // Validate that there are no 'holes' in our versions
    for (size_t ii = 1; ii < max_version; ++ii) {
        if (getErrorMap(ii).empty()) {
            throw std::runtime_error(errkey + ": Missing error map version " +
                                     std::to_string(ii));
        }
    }
}

const std::string& Settings::getErrorMap(size_t version) const {
    const static std::string empty("");
    if (error_maps.empty()) {
        return empty;
    }

    version = std::min(version, error_maps.size()-1);
    return error_maps[version];
}


void Settings::notify_changed(const std::string& key) {
    auto iter = change_listeners.find(key);
    if (iter != change_listeners.end()) {
        for (auto& listener : iter->second) {
            listener(key, *this);
        }
    }
}

BreakpadSettings::BreakpadSettings(const cJSON* json) {
    auto* obj = cJSON_GetObjectItem(const_cast<cJSON*>(json), "enabled");
    if (obj == nullptr) {
        throw std::invalid_argument(
            "\"breakpad\" settings MUST contain \"enabled\" attribute");
    }
    if (obj->type == cJSON_True) {
        enabled = true;
    } else if (obj->type == cJSON_False) {
        enabled = false;
    } else {
        throw std::invalid_argument(
            "\"breakpad:enabled\" settings must be a boolean value");
    }

    obj = cJSON_GetObjectItem(const_cast<cJSON*>(json), "minidump_dir");
    if (obj == nullptr) {
        if (enabled) {
            throw std::invalid_argument(
                "\"breakpad\" settings MUST contain \"minidump_dir\" attribute when enabled");
        }
    } else if (obj->type != cJSON_String) {
        throw std::invalid_argument(
            "\"breakpad:minidump_dir\" settings must be a string");
    } else {
        minidump_dir.assign(obj->valuestring);
        if (enabled) {
            if (!cb::io::isDirectory(minidump_dir)) {
                throw_missing_file_exception("breakpad:minidump_dir", obj);
            }
        }
    }

    obj = cJSON_GetObjectItem(const_cast<cJSON*>(json), "content");
    if (obj != nullptr) {
        if (obj->type != cJSON_String) {
            throw std::invalid_argument(
                "\"breakpad:content\" settings must be a string");
        }
        if (strcmp(obj->valuestring, "default") != 0) {
            throw std::invalid_argument(
                "\"breakpad:content\" settings must set to \"default\"");
        }
        content = BreakpadContent::Default;
    }
}

std::string ClientCertAuth::cJSON_GetObjectString(cJSON* obj,
                                                  const char* key,
                                                  bool must = false) {
    auto* value = cJSON_GetObjectItem(obj, key);
    if (!value) {
        if (must) {
            std::ostringstream stringStream;
            stringStream
                    << "\"ClientCertAuth:client_cert_auth\" must contain \""
                    << key << "\"";
            throw std::invalid_argument(stringStream.str());
        } else {
            return "";
        }
    }
    if (value->type != cJSON_String) {
        std::ostringstream stringStream;
        stringStream << "\"ClientCertAuth:client_cert_auth\":" << key
                     << " must be string";
        throw std::invalid_argument(stringStream.str());
    }
    return value->valuestring;
}

ClientCertAuth::ClientCertAuth(cJSON* obj) {
    if (obj->type == cJSON_String) {
        store(obj->valuestring);
        certUser = createCertUser("", "", "");
        return;
    }
    auto stateVal = cJSON_GetObjectString(obj, "state", true);
    auto pathVal = cJSON_GetObjectString(obj, "path");
    auto prefixVal = cJSON_GetObjectString(obj, "prefix");
    auto delimiterVal = cJSON_GetObjectString(obj, "delimiter");
    auto createUser = createCertUser(pathVal, prefixVal, delimiterVal);
    store(stateVal);
    ClientCertAuth::prefix = prefixVal;
    ClientCertAuth::type = pathVal;
    ClientCertAuth::delimiter = delimiterVal;
    certUser.reset(createUser.release());
}
