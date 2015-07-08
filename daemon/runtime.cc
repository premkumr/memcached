/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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
#include "config.h"
#include "runtime.h"

#include <string>
#include <platform/platform.h>

class SslCipherList {
public:
    SslCipherList() {
        cb_mutex_initialize(&mutex);
    }

    ~SslCipherList() {
        cb_mutex_destroy(&mutex);
    }

    void setList(const char *l) {
        cb_mutex_enter(&mutex);
        if (l == NULL) {
            list.resize(0);
        } else {
            list.assign(l);
        }
        cb_mutex_exit(&mutex);
    }

    void setCipherList(SSL_CTX *ctx, EXTENSION_LOGGER_DESCRIPTOR *logger) {
        cb_mutex_enter(&mutex);
        if (list.length()) {
            if (SSL_CTX_set_cipher_list(ctx, list.c_str()) == 0) {
                logger->log(EXTENSION_LOG_WARNING, NULL,
                            "Failed to select any of the "
                            "requested ciphers (%s)",
                            list.c_str());
            }
        }
        cb_mutex_exit(&mutex);
    }

private:
    std::string list;
    cb_mutex_t mutex;
} sslCipherList;

void set_ssl_cipher_list(const char *list) {
    sslCipherList.setList(list);
}

void set_ssl_ctx_cipher_list(SSL_CTX *ctx, EXTENSION_LOGGER_DESCRIPTOR *logger) {
    sslCipherList.setCipherList(ctx, logger);
}

char *locate_ssl_json(void) {
    // We don't know where the "root" of the couchbase installation is
    // but we know where the SASL_PW file is..
    char *env = getenv("ISASL_PWFILE");
    if (env == NULL) {
        return NULL;
    }

    std::string path(env);
#ifdef WIN32
    // Make sure that the path is in unix format
    std::replace(path.begin(), path.end(), '\\', '/');
#endif

    std::string::size_type position = path.find("/var/lib/couchbase/isasl.pw");
    if (position == std::string::npos) {
        return NULL;
    }
    path.resize(position);
    path.append("/etc/security/ssl.json");

#ifdef WIN32
    // Make sure that the path is in Windows format
    std::replace(path.begin(), path.end(), '/', '\\');
#endif

    return strdup(path.c_str());
}
