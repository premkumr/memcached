/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2017 Couchbase, Inc.
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

/*
 * Unfortunately Apple deprecated the use of OpenSSL in (at least) Mavericks
 * and added attributes to the methods in the header causing the code to
 * emit a ton of warnings. I guess I should wrap all of the methods we're
 * using into another library so that I don't have to disable the deprecation
 * warnings for other code. We know of this one, but we don't want to make
 * an apple specific version (I guess the other option would be to drop the
 * support for ssl on mac ;-)
 */
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <memory>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

namespace cb {
namespace openssl {
struct X509deletor {
    void operator()(X509* cert) {
        X509_free(cert);
    }
};

using unique_x509_ptr = std::unique_ptr<X509, X509deletor>;
}
}

