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
#pragma once

#include "config.h"

#include "settings.h"

#include <cJSON.h>
#include <cbsasl/cbsasl.h>
#include <memcached/rbac.h>
#include <string>

struct LIBEVENT_THREAD;
class ListeningPort;
class Bucket;

/**
 * The structure representing a connection in memcached.
 */
class Connection {
public:
    enum class Priority : uint8_t {
        High,
        Medium,
        Low
    };

    virtual ~Connection();

    Connection(const Connection&) = delete;

    /**
     * Return an identifier for this connection. To be backwards compatible
     * this is the socket filedescriptor (or the socket handle casted to an
     * unsigned integer on windows).
     */
    uint32_t getId() const {
        return uint32_t(socketDescriptor);
    }

    /**
     *  Get the socket descriptor used by this connection.
     */
    SOCKET getSocketDescriptor() const {
        return socketDescriptor;
    }

    /**
     * Set the socket descriptor used by this connection
     */
    void setSocketDescriptor(SOCKET sfd) {
        Connection::socketDescriptor = sfd;
    }

    bool isSocketClosed() const {
        return socketDescriptor == INVALID_SOCKET;
    }

    /**
     * Resolve the name of the local socket and the peer for the connected
     * socket.
     * @param listening True if the local socket is a listening socket.
     */
    void resolveConnectionName(bool listening);

    const std::string& getPeername() const {
        return peername;
    }

    const std::string& getSockname() const {
        return sockname;
    }

    /**
     * Returns a descriptive name for the connection, of the form:
     *   "[peer_name - local_name ]"
     * (system) is appended to the string for system connections.
     */
    const std::string& getDescription() const {
        return description;
    }

    /**
     * Tell the connection to initiate it's shutdown logic
     */
    virtual void initiateShutdown() {
        throw std::runtime_error("Not implemented");
    }

    /**
     * Signal a connection if it's idle
     *
     * @param logbusy set to true if you want to log the connection details
     *                if the connection isn't idle
     * @param workerthead the id of the workerthread (for logging purposes)
     */
    virtual void signalIfIdle(bool logbusy, int workerthread) {

    }

    /**
     * Terminate the eventloop for the current event base. This method doesn't
     * really fit as a member for the class, but I don't want clients to access
     * the libevent details from outside the class (so I didn't want to make
     * a "getEventBase()" method.
     */
    void eventBaseLoopbreak() {
        event_base_loopbreak(base);
    }

    /**
     * Is the connection representing a system internal user
     */
    bool isInternal() const {
        return internal;
    }

    /**
     * Specify if this connection is representing an internal user.
     * An internal user is a user which is used by one of the components
     * in Couchbase (like ns_server, indexer etc).
     */
    void setInternal(bool internal) {
        Connection::internal = internal;
    }

    /**
     * Update the username to reflect what the user used from the SASL
     * authentication.
     */
    void resetUsernameCache();


    bool isAuthenticated() const {
        return authenticated;
    }

    void setAuthenticated(bool authenticated) {
        Connection::authenticated = authenticated;
        if (authenticated) {
            updateDescription();
            privilegeContext = cb::rbac::createContext(username, "");
        } else {
            resetUsernameCache();
            privilegeContext = cb::rbac::PrivilegeContext{};
        }
    }

    const Priority& getPriority() const {
        return priority;
    }

    virtual void setPriority(const Priority& priority) {
        Connection::priority = priority;
    }

    virtual const Protocol getProtocol() const = 0;

    /**
     * Create a cJSON representation of the members of the connection
     * Caller is responsible for freeing the result with cJSON_Delete().
     */
    virtual cJSON* toJSON() const;

    /**
     * Enable or disable TCP NoDelay on the underlying socket
     *
     * @return true on success, false otherwise
     */
    bool setTcpNoDelay(bool enable);

    /**
     * Get the username this connection is authenticated as
     *
     * NOTE: the return value should not be returned by the client
     */
    const char* getUsername() const {
        return username.c_str();
    }

    /**
     * Get the domain where the user is defined (builtin or saslauthd)
     */
    cb::sasl::Domain getDomain() const {
        return domain;
    }

    cbsasl_conn_t* getSaslConn() const {
        return sasl_conn.get();
    }

    /**
     * Get the current reference count
     */
    uint8_t getRefcount() const {
        return refcount;
    }

    void incrementRefcount() {
        ++refcount;
    }

    void decrementRefcount() {
        --refcount;
    }

    Connection* getNext() const {
        return next;
    }

    void setNext(Connection* next) {
        Connection::next = next;
    }

    LIBEVENT_THREAD* getThread() const {
        return thread.load(std::memory_order_relaxed);
    }

    void setThread(LIBEVENT_THREAD* thread) {
        Connection::thread.store(thread,
                                 std::memory_order::memory_order_relaxed);
    }

    /**
     * @todo this should be pushed down to MCBP, doesn't apply to everyone else
     */
    virtual bool isPipeConnection() {
        return false;
    }

    /**
     * @todo this should be pushed down to MCBP, doesn't apply to everyone else
     */
    virtual bool isSupportsMutationExtras() const {
        return true;
    }

    in_port_t getParentPort() const {
        return parent_port;
    }

    void setParentPort(in_port_t parent_port) {
        Connection::parent_port = parent_port;
    }

    virtual bool isTAP() const {
        return false;
    }

    virtual bool isDCP() const {
        return false;
    }

    /**
     * Check if this connection is in posession of the requested privilege
     *
     * @param privilege the privilege to check for
     * @return Ok - the connection holds the privilege
     *         Fail - the connection is missing the privilege
     *         Stale - the authentication context is stale
     */
    cb::rbac::PrivilegeAccess checkPrivilege(cb::rbac::Privilege privilege);

    int getBucketIndex() const {
        return bucketIndex.load(std::memory_order_relaxed);
    }

    void setBucketIndex(int bucketIndex);

    Bucket& getBucket() const;

    ENGINE_HANDLE_V1* getBucketEngine() const {
        return bucketEngine;
    };

    ENGINE_HANDLE* getBucketEngineAsV0() const {
        return reinterpret_cast<ENGINE_HANDLE*>(bucketEngine);
    }

    void setBucketEngine(ENGINE_HANDLE_V1* bucketEngine) {
        Connection::bucketEngine = bucketEngine;
    };

    void* getEngineStorage() const {
        return engine_storage;
    }

    void setEngineStorage(void* engine_storage) {
        Connection::engine_storage = engine_storage;
    }

    virtual bool shouldDelete() {
        return false;
    }

    virtual void runEventLoop(short which) = 0;


    int getClustermapRevno() const {
        return clustermap_revno;
    }

    void setClustermapRevno(int clustermap_revno) {
        Connection::clustermap_revno = clustermap_revno;
    }

    bool isTraceEnabled() const {
        return trace_enabled;
    }

    void setTraceEnabled(bool trace_enabled) {
        Connection::trace_enabled = trace_enabled;
    }

    /**
     * Restart the authentication (this clears all of the authentication
     * data...)
     */
    void restartAuthentication();

    bool isXerrorSupport() const {
        return xerror_support;
    }

    void setXerrorSupport(bool xerror_support) {
        Connection::xerror_support = xerror_support;
    }

    bool isCollectionsSupported() const {
        return collections_support;
    }

    void setCollectionsSupported(bool collections_support) {
        Connection::collections_support = collections_support;
    }

    DocNamespace getDocNamespace() const {
        if (isCollectionsSupported()) {
            return DocNamespace::Collections;
        } else {
            return DocNamespace::DefaultCollection;
        }
    }

    /**
     * Remap the current error code
     *
     * The method modifies the input code and returns the mapped value
     * (to make the function a bit easier to use).
     *
     * Depending on which features the client have enabled the method
     * may either just return the input value, map it to a different value
     * (like ENGINE_DISCONNECT if the client hasn't enabled the extened
     * error codes).
     *
     * @param code The code to map (will be changed on return)
     * @return the mapped value.
     */
    ENGINE_ERROR_CODE remapErrorCode(ENGINE_ERROR_CODE code) const;

protected:
    Connection(SOCKET sfd, event_base* b);

    Connection(SOCKET sfd, event_base* b,
               const ListeningPort& interface);

    /**
     * Update the description string for the connection. This
     * method should be called every time the authentication data
     * (or the sockname/peername) changes
     */
    void updateDescription();

    /**
     * The actual socket descriptor used by this connection
     */
    SOCKET socketDescriptor;

    /**
     * The event base this connection is bound to
     */
    event_base *base;

    /**
     * The current privilege context
     */
    cb::rbac::PrivilegeContext privilegeContext;

    /**
     * The SASL object used to do sasl authentication
     */
    unique_cbsasl_conn_t sasl_conn;

    /** Is this a system internal connection */
    bool internal;

    /** Is the connection authenticated or not */
    bool authenticated;

    /** The username authenticated as */
    std::string username;

    /** The domain where the user is defined */
    cb::sasl::Domain domain;

    /** The description of the connection */
    std::string description;

    /** Is tcp nodelay enabled or not? */
    bool nodelay;

    /** number of references to the object */
    uint8_t refcount;

    /**
     * Pointer to engine-specific data which the engine has requested the server
     * to persist for the life of the connection.
     * See SERVER_COOKIE_API::{get,store}_engine_specific()
     */
    void* engine_storage;

    /* Used for generating a list of Connection structures */
    Connection* next;

    /** Pointer to the thread object serving this connection */
    std::atomic<LIBEVENT_THREAD*> thread;

    /** Listening port that creates this connection instance */
    in_port_t parent_port;

    /**
     * The index of the connected bucket
     */
    std::atomic_int bucketIndex;

    /**
     * The engine interface for the connected bucket
     */
    ENGINE_HANDLE_V1* bucketEngine;

    /** Name of the peer if known */
    std::string peername;

    /** Name of the local socket if known */
    std::string sockname;

    /** The connections priority */
    Priority priority;

    /** The cluster map revision used by this client */
    int clustermap_revno;

    /**
     * is trace enabled for this connection or not. Initially we'll just
     * have an on/off switch.. We'll be refactoring this into multiple
     * subgroups at some point.
     */
    bool trace_enabled;

    /**
     * Is XERROR supported for this connection or not (or should we just
     * silently disconnect the client)
     */
    bool xerror_support;

    /**
     * Is COLLECTIONS supported for this connection or not. Collection aware
     * clients are allowed to encode operations to occur against their defined
     * collections or the legacy default collection (and receive new errors).
     * Collection aware clients also see mutations/deletions for all collection
     * if they are subscribed to DCP.
     * Collections unaware clients can only target operations at the legacy
     * default collection and receive no new errors. They also only ever see
     * default collection mutations/deletions etc... when subscribed to DCP.
     */
    bool collections_support;
};

/**
 * Convert a priority to a textual representation
 */
const char* to_string(const Connection::Priority& priority);
