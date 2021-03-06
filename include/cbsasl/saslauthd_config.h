/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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

#include <string>

#ifndef CBSASL_CBSASL_H
#error "Include <cbsasl/cbsasl.h>"
#endif

namespace cb {
namespace sasl {
namespace saslauthd {

/**
 * Set the path to use to access access saslauthd
 */
CBSASL_PUBLIC_API
void set_socketpath(const std::string& path);

/**
 * Get the path to the saslauthd socketpath
 */

CBSASL_PUBLIC_API
std::string get_socketpath();

/**
 * Is saslauthd configured or not (may be used if you just want to
 * know if it exists or not (it grabs the socketpath and verifies
 * that it exists)
 */
CBSASL_PUBLIC_API
bool is_configured();
}
}
}
