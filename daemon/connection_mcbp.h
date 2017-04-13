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

// @todo make this file "standalone" with includes and forward decl.

#include "config.h"

#include "datatype.h"
#include "dynamic_buffer.h"
#include "log_macros.h"
#include "net_buf.h"
#include "settings.h"
#include "sslcert.h"
#include "statemachine_mcbp.h"

#include <cJSON.h>
#include <cbsasl/cbsasl.h>
#include <daemon/protocol/mcbp/command_context.h>
#include <daemon/protocol/mcbp/steppable_command_context.h>
#include <memcached/openssl.h>
#include <platform/cb_malloc.h>
#include <platform/make_unique.h>
#include <platform/sized_buffer.h>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "connection.h"
#include "cookie.h"
#include "task.h"

/**
 * The SslContext class is a holder class for all of the ssl-related
 * information used by the connection object.
 */
class SslContext {
public:
    SslContext()
        : enabled(false),
          connected(false),
          error(false),
          application(nullptr),
          network(nullptr),
          ctx(nullptr),
          client(nullptr),
          totalRecv(0),
          totalSend(0) {
        in.total = 0;
        in.current = 0;
        out.total = 0;
        out.current = 0;
    }

    ~SslContext();

    /**
     * Is ssl enabled for this connection or not?
     */
    bool isEnabled() const {
        return enabled;
    }

    /**
     * Is the client fully connected over ssl or not?
     */
    bool isConnected() const {
        return connected;
    }

    /**
     * Set the status of the connected flag
     */
    void setConnected() {
        connected = true;
    }

    /**
     * Is there an error on the SSL stream?
     */
    bool hasError() const {
        return error;
    }

    /**
     * Enable SSL for this connection.
     *
     * @param cert the certificate file to use
     * @param pkey the private key file to use
     * @return true if success, false if we failed to enable SSL
     */
    bool enable(const std::string& cert, const std::string& pkey);

    /**
     * Disable SSL for this connection
     */
    void disable();

    /**
     * Try to fill the SSL stream with as much data from the network
     * as possible.
     *
     * @param sfd the socket to read data from
     */
    void drainBioRecvPipe(SOCKET sfd);

    /**
     * Try to drain the SSL stream with as much data as possible and
     * send it over the network.
     *
     * @param sfd the socket to write data to
     */
    void drainBioSendPipe(SOCKET sfd);

    bool moreInputAvailable() const {
        return (in.current < in.total);
    }

    bool morePendingOutput() const {
        return (out.total > 0);
    }

    /**
     * Dump the list of available ciphers to the log
     * @param id the connection id. Its only used in the
     *            log messages.
     */
    void dumpCipherList(uint32_t id) const;

    int accept() {
        return SSL_accept(client);
    }

    int getError(int errormask) const {
        return SSL_get_error(client, errormask);
    }

    int read(void* buf, int num) {
        return SSL_read(client, buf, num);
    }

    int write(const void* buf, int num) {
        return SSL_write(client, buf, num);
    }

    int peek(void* buf, int num) {
        return SSL_peek(client, buf, num);
    }

    std::pair<ClientCertUser::Status, std::string> getCertUserName();
    /**
     * Get a JSON description of this object.. caller must call cJSON_Delete()
     */
    cJSON* toJSON() const;

protected:
    bool enabled;
    bool connected;
    bool error;
    BIO* application;
    BIO* network;
    SSL_CTX* ctx;
    SSL* client;
    struct {
        // The data located in the buffer
        std::vector<char> buffer;
        // The number of bytes currently stored in the buffer
        size_t total;
        // The current offset of the buffer
        size_t current;
    } in, out;

    // Total number of bytes received on the network
    size_t totalRecv;
    // Total number of bytes sent to the network
    size_t totalSend;
};

class SaslCommandContext : public CommandContext {
public:
    SaslCommandContext(std::shared_ptr<Task>& t)
    : task(t) { }

    std::shared_ptr<Task> task;
};

class McbpConnection : public Connection {
public:
    McbpConnection() = delete;
    McbpConnection(SOCKET sfd, event_base* b);

    McbpConnection(SOCKET sfd, event_base* b, const ListeningPort& ifc);

    virtual ~McbpConnection();


    virtual void initiateShutdown() override;

    virtual void signalIfIdle(bool logbusy, int workerthread) override;


    virtual void setPriority(const Priority& priority) override;

    void setState(TaskFunction next_state);

    TaskFunction getState() const {
        return stateMachine->getCurrentTask();
    }

    const char* getStateName() const {
        return stateMachine->getCurrentTaskName();
    }

    const TAP_ITERATOR getTapIterator() const {
        return tap_iterator;
    }

    void setTapIterator(TAP_ITERATOR tap_iterator) {
        McbpConnection::tap_iterator = tap_iterator;
    }

    virtual bool isTAP() const override {
        return tap_iterator != nullptr;
    }

    virtual bool isDCP() const override {
        return dcp;
    }

    void setDCP(bool dcp) {
        McbpConnection::dcp = dcp;
    }

    bool isDcpXattrAware() const {
        return dcpXattrAware;
    }

    void setDcpXattrAware(bool dcpXattrAware) {
        // @todo Keeping this as NOTICE while waiting for ns_server
        //       support for xattr over DCP (to make it easier to debug
        ///      see MB-22468
        LOG_NOTICE(this, "%u: DCP connection is %sXATTR aware %s",
                   getId(),
                   dcpXattrAware ? "" : "not ",
                   getDescription().c_str());
        McbpConnection::dcpXattrAware = dcpXattrAware;
    }

    bool isDcpNoValue() const {
        return dcpNoValue;
    }

    void setDcpNoValue(bool dcpNoValue) {
        // @todo Keeping this as NOTICE while waiting for ns_server
        //       support for xattr over DCP (to make it easier to debug
        ///      see MB-22468
        LOG_NOTICE(this, "%u: DCP contains keys and %svalues %s",
                   getId(),
                   dcpNoValue ? "not " : "",
                   getDescription().c_str());

        McbpConnection::dcpNoValue = dcpNoValue;
    }

    virtual cJSON* toJSON() const override;


    virtual const Protocol getProtocol() const override;

    /**
     * Log the current connection if its execution time exceeds the
     * threshold for the command
     *
     * @param elapsed the number of ms elapsed while executing the command
     *
     * @todo refactor this into the command object when we introduce them
     */
    void maybeLogSlowCommand(const std::chrono::milliseconds& elapsed) const;

    /**
     * Return the opaque value for the command being processed
     */
    uint32_t getOpaque() const {
        return binary_header.request.opaque;
    }

    uint8_t getCmd() const {
        return cmd;
    }

    void setCmd(uint8_t cmd) {
        McbpConnection::cmd = cmd;
    }

    /**
     * Return the key of the currently processing command.
     * @return the buffer to the key.
     */
    cb::const_char_buffer getKey() const {
        auto *pkt = reinterpret_cast<const char *>(getPacket(cookie));
        cb::const_char_buffer ret;
        ret.len = binary_header.request.keylen;
        ret.buf = pkt + sizeof binary_header.bytes + binary_header.request.extlen;
        return ret;
    }

    /**
     * Get a printable key from the header. Replace all non-printable
     * charachters with '.'
     */
    std::string getPrintableKey() const;

    const protocol_binary_request_header& getBinaryHeader() const {
        return binary_header;
    }

    /* Binary protocol stuff */
    /* This is where the binary header goes */
    protocol_binary_request_header binary_header;

    // Returns true if a string representation of the specified status code
    // should be included in the response body (in addition to in the reponse
    // header) for the current command.
    bool includeErrorStringInResponseBody(
        protocol_binary_response_status err) const;

    /**
     * Decrement the number of events to process and return the new value
     */
    int decrementNumEvents() {
        return --numEvents;
    }

    /**
     * Set the number of events to process per timeslice of the worker
     * thread before yielding.
     */
    void setNumEvents(int nevents) {
        McbpConnection::numEvents = nevents;
    }

    /**
     * Get the maximum number of events we should process per invocation
     * for a connection object (to avoid starvation of other connections)
     */
    int getMaxReqsPerEvent() const {
        return max_reqs_per_event;
    }

    /**
     * Update the settings in libevent for this connection
     *
     * @param mask the new event mask to get notified about
     */
    bool updateEvent(const short new_flags);

    /**
     * Reapply the event mask (in case of a timeout we might want to do
     * that)
     */
    bool reapplyEventmask();

    /**
     * Unregister the event structure from libevent
     * @return true if success, false otherwise
     */
    bool unregisterEvent();

    /**
     * Register the event structure in libevent
     * @return true if success, false otherwise
     */
    bool registerEvent();

    bool isRegisteredInLibevent() const {
        return registered_in_libevent;
    }

    short getEventFlags() const {
        return ev_flags;
    }

    short getCurrentEvent() const {
        return currentEvent;
    }

    void setCurrentEvent(short ev) {
        currentEvent = ev;
    }

    /** Is the current event a readevent? */
    bool isReadEvent() const {
        return currentEvent & EV_READ;
    }

    /** Is the current event a writeevent? */
    bool isWriteEvent() const {
        return currentEvent & EV_WRITE;
    }

    /**
     * Shrinks a connection's buffers if they're too big.  This prevents
     * periodic large "get" requests from permanently chewing lots of server
     * memory.
     *
     * This should only be called in between requests since it can wipe output
     * buffers!
     */
    void shrinkBuffers();

    /**
     * Receive data from the socket
     *
     * @param where to store the result
     * @param nbytes the size of the buffer
     *
     * @return the number of bytes read, or -1 for an error
     */
    virtual int recv(char* dest, size_t nbytes);

    /**
     * Send data over the socket
     *
     * @param m the message header to send
     * @return the number of bytes sent, or -1 for an error
     */
    virtual int sendmsg(struct msghdr* m);


    enum class TransmitResult {
        /** All done writing. */
            Complete,
        /** More data remaining to write. */
            Incomplete,
        /** Can't write any more right now. */
            SoftError,
        /** Can't write (c->state is set to conn_closing) */
            HardError
    };

    /**
     * Transmit the next chunk of data from our list of msgbuf structures.
     *
     * Returns:
     *   Complete   All done writing.
     *   Incomplete More data remaining to write.
     *   SoftError Can't write any more right now.
     *   HardError Can't write (c->state is set to conn_closing)
     */
    TransmitResult transmit();

    enum class TryReadResult {
        /** Data received on the socket and ready to parse */
            DataReceived,
        /** No data received on the socket */
            NoDataReceived,
        /** The client closed the connection */
            SocketClosed,
        /** An error occurred on the socket */
            SocketError,
        /** Failed to allocate more memory for the input buffer */
            MemoryError
    };

    /**
     * read from network as much as we can, handle buffer overflow and
     * connection close. Before reading, move the remaining incomplete fragment
     * of a command (if any) to the beginning of the buffer.
     *
     * @return enum try_read_result
     */
    TryReadResult tryReadNetwork();

    const TaskFunction getWriteAndGo() const {
        return write_and_go;
    }

    void setWriteAndGo(TaskFunction write_and_go) {
        McbpConnection::write_and_go = write_and_go;
    }

    char* getRitem() const {
        return ritem;
    }

    void setRitem(char* ritem) {
        McbpConnection::ritem = ritem;
    }

    uint32_t getRlbytes() const {
        return rlbytes;
    }

    void setRlbytes(uint32_t rlbytes) {
        McbpConnection::rlbytes = rlbytes;
    }

    void* getItem() const {
        return item;
    }

    void setItem(void* item) {
        McbpConnection::item = item;
    }

    /**
     * Get the number of entries in use in the IO Vector
     */
    int getIovUsed() const {
        return iovused;
    }

    /**
     * Adds a message header to a connection.
     *
     * @param reset set to true to reset all message headers
     * @throws std::bad_alloc
     */
    void addMsgHdr(bool reset);

    /**
     * Add a chunk of memory to the the IO vector to send
     *
     * @param buf pointer to the data to send
     * @param len number of bytes to send
     * @throws std::bad_alloc
     */
    void addIov(const void* buf, size_t len);

    /**
     * Release all of the items we've saved a reference to
     */
    void releaseReservedItems() {
        ENGINE_HANDLE* handle = reinterpret_cast<ENGINE_HANDLE*>(bucketEngine);
        for (auto* it : reservedItems) {
            bucketEngine->release(handle, this, it);
        }
        reservedItems.clear();
    }

    /**
     * Put an item on our list of reserved items (which we should release
     * at a later time through releaseReservedItems).
     *
     * @return true if success, false otherwise
     */
    bool reserveItem(void* item) {
        try {
            reservedItems.push_back(item);
            return true;
        } catch (std::bad_alloc) {
            return false;
        }
    }

    void releaseTempAlloc() {
        for (auto* ptr : temp_alloc) {
            cb_free(ptr);
        }
        temp_alloc.resize(0);
    }

    bool pushTempAlloc(char* ptr) {
        try {
            temp_alloc.push_back(ptr);
            return true;
        } catch (std::bad_alloc) {
            LOG_WARNING(this,
                        "%u: FATAL: failed to allocate space to keep temporary buffer",
                        getId());
            return false;
        }
    }

    bool isNoReply() const {
        return noreply;
    }

    void setNoReply(bool noreply) {
        McbpConnection::noreply = noreply;
    }


    /**
     * Enable the datatype which corresponds to the feature
     *
     * @param feature mcbp::Feature::JSON|XATTR|SNAPPY
     * @throws if feature does not correspond to a datatype
     */
    void enableDatatype(mcbp::Feature feature) {
        datatype.enable(feature);
    }

    /**
     * Disable all the datatypes
     */
    void disableAllDatatypes() {
        datatype.disableAll();
    }

    /**
     * Given the input datatype, return only those which are enabled for the
     * connection.
     *
     * @param dtype the set to intersect against the enabled set
     * @returns the intersection of the enabled bits and dtype
     */
    protocol_binary_datatype_t getEnabledDatatypes(
            protocol_binary_datatype_t dtype) const {
        return datatype.getIntersection(dtype);
    }

    /**
     * @return true if the all of the dtype datatypes are all enabled
     */
    bool isDatatypeEnabled(protocol_binary_datatype_t dtype) const {
        return datatype.isEnabled(dtype);
    }

    /**
     * @return true if JSON datatype is enabled
     */
    bool isJsonEnabled() const {
        return datatype.isJsonEnabled();
    }

    /**
     * @return true if compression datatype is enabled
     */
    bool isSnappyEnabled() const {
        return datatype.isSnappyEnabled();
    }

    /**
     * @return true if the XATTR datatype is enabled
     */
    bool isXattrEnabled() const {
        return datatype.isXattrEnabled();
    }

    virtual bool isSupportsMutationExtras() const override {
        return supports_mutation_extras;
    }

    void setSupportsMutationExtras(bool supports_mutation_extras) {
        McbpConnection::supports_mutation_extras = supports_mutation_extras;
    }

    /**
     * Clear the dynamic buffer
     */
    void clearDynamicBuffer() {
        dynamicBuffer.clear();
    }

    /**
     * Grow the dynamic buffer to
     */
    bool growDynamicBuffer(size_t needed) {
        return dynamicBuffer.grow(needed);
    }

    DynamicBuffer& getDynamicBuffer() {
        return dynamicBuffer;
    }

    hrtime_t getStart() const {
        return start;
    }

    void setStart(hrtime_t start) {
        McbpConnection::start = start;
    }

    uint64_t getCAS() const {
        return cas;
    }

    void setCAS(uint64_t cas) {
        McbpConnection::cas = cas;
    }


    const ENGINE_ERROR_CODE& getAiostat() const {
        return aiostat;
    }

    void setAiostat(const ENGINE_ERROR_CODE& aiostat) {
        McbpConnection::aiostat = aiostat;
    }

    bool isEwouldblock() const {
        return ewouldblock;
    }

    void setEwouldblock(bool ewouldblock) {
        McbpConnection::ewouldblock = ewouldblock;
    }

    /**
     *  Get the command context stored for this command
     */
    CommandContext* getCommandContext() const {
        return commandContext.get();
    }

    /**
     * Get the command context stored for this command as
     * the given type or make it if it doesn't exist
     *
     * @tparam ContextType CommandContext type to create
     * @return the context object
     * @throws std::logic_error if the object is the wrong type
     */
    template <typename ContextType, typename... Args>
    ContextType& obtainContext(Args&&... args) {
        auto* context = commandContext.get();
        if (context == nullptr) {
            auto* ret = new ContextType(std::forward<Args>(args)...);
            commandContext.reset(ret);
            return *ret;
        }
        auto* ret = dynamic_cast<ContextType*>(context);
        if (ret == nullptr) {
            throw std::logic_error(
                    std::string("McbpConnection::obtainContext<") +
                    typeid(ContextType).name() +
                    ">(): context is not the requested type");
        }
        return *ret;
    }

    /**
     * Get the command context which SHOULD be a steppable command context
     *
     * @return the context object
     * @throws std::logic_error if the object is non-existent or the wrong type
     */
    SteppableCommandContext& getSteppableCommandContext() const {
        auto* context = commandContext.get();
        if (context == nullptr) {
            throw std::logic_error(
                "McbpConnection::getSteppableCommandContext(): context should not be nullptr");
        }
        auto* ret = dynamic_cast<SteppableCommandContext*>(context);
        if (ret == nullptr) {
            throw std::logic_error(
                "McbpConnection::getSteppableCommandContext(): context is not steppable");
        }
        return *ret;
    }

    /**
     *  Set the command context stored for this command
     */
    void setCommandContext(CommandContext* cmd_context) {
        McbpConnection::commandContext.reset(cmd_context);
    }

    /**
     * Reset the command context
     *
     * Release the allocated resources and set the command context to nullptr
     */
    void resetCommandContext() {
        commandContext.reset();
    }

    /**
     * Log the start of processing a command received from the client in the
     * generic form which (may change over time, but currently it) looks like:
     *
     *     id> COMMAND KEY
     */
    void logCommand() const;

    /**
     * Log the end of processing a command and the result of the command:
     *
     *     id< COMMAND KEY - STATUS
     *
     * @param code The execution result
     */
    void logResponse(ENGINE_ERROR_CODE code) const;

    /**
     * Try to enable SSL for this connection
     *
     * @param cert the SSL certificate to use
     * @param pkey the SSL private key to use
     * @return true if successful, false otherwise
     */
    bool enableSSL(const std::string& cert, const std::string& pkey) {
        if (ssl.enable(cert, pkey)) {
            if (settings.getVerbose() > 1) {
                ssl.dumpCipherList(getId());
            }

            return true;
        }

        return false;
    }

    /**
     * Disable SSL for this connection
     */
    void disableSSL() {
        ssl.disable();
    }

    /**
     * Is SSL enabled for this connection or not?
     *
     * @return true if the connection is running over SSL, false otherwise
     */
    bool isSslEnabled() const {
        return ssl.isEnabled();
    }

    /**
     * Do we have any pending input data on this connection?
     */
    bool havePendingInputData() {
        int block = (read.bytes > 0);

        if (!block && ssl.isEnabled()) {
            char dummy;
            block |= ssl.peek(&dummy, 1);
        }

        return block != 0;
    }

    /**
     * Try to find RBAC user from the client ssl cert
     *
     * @return true if username has been linked to RBAC or ssl cert was not
     * presented by the client.
     */
    bool tryAuthFromSslCert(const std::string& userName);

    virtual bool shouldDelete() override;

    virtual void runEventLoop(short which) override;

    /** Read buffer */
    struct net_buf read;

    /** Write buffer */
    struct net_buf write;

    const void* getCookie() const {
        return &cookie;
    }

    Cookie& getCookieObject() {
        return cookie;
    }

    /**
     * Obtain a pointer to the packet for the Cookie's connection
     */
    static void* getPacket(const Cookie& cookie) {
        auto c = static_cast<McbpConnection*>(cookie.connection);
        return (c->read.curr -
               (c->binary_header.request.bodylen + sizeof(c->binary_header)));
    }

    /**
     *  Invoke the validator function(s) for the command
     */
    protocol_binary_response_status validateCommand(protocol_binary_command command);

    /**
     * Is SASL disabled for this connection? (connection authenticated with
     * SSL certificates will disable the possibility re-authenticate over
     * SASL)
     */
    bool isSaslAuthDisabled() const {
        return saslAuthDisabled;
    }

protected:
    void runStateMachinery();

    /**
     * Initialize the event structure and add it to libevent
     *
     * @return true upon success, false otherwise
     */
    bool initializeEvent();

    void logResponse(const char* reason) const;

    /**
     * The state machine we're currently using
     */
    std::unique_ptr<McbpStateMachine> stateMachine;

    /** The iterator function to use to traverse the TAP stream */
    TAP_ITERATOR tap_iterator;

    /** Is this connection used by a DCP connection? */
    bool dcp;

    /** Is this DCP channel XAttrAware */
    bool dcpXattrAware;

    /** Shuld values be stripped off? */
    bool dcpNoValue;

    int max_reqs_per_event; /** The maximum requests we can process in a worker
                                thread timeslice */
    /**
     * number of events this connection can process in a single worker
     * thread timeslice
     */
    int numEvents;

    /** current command being processed */
    uint8_t cmd;

    // Members related to libevent

    /** Is the connection currently registered in libevent? */
    bool registered_in_libevent;
    /** The libevent object */
    struct event event;
    /** The current flags we've registered in libevent */
    short ev_flags;
    /** which events were just triggered */
    short currentEvent;
    /** When we inserted the object in libevent */
    rel_time_t ev_insert_time;
    /** Do we have an event timeout or not */
    bool ev_timeout_enabled;
    /** If ev_timeout_enabled is true, the current timeout in libevent */
    rel_time_t ev_timeout;

    /** which state to go into after finishing current write */
    TaskFunction write_and_go;

    /** when we read in an item's value, it goes here */
    char* ritem;

    /* read 'left' bytes - how many bytes of data remain to be read for the
     * nread state
     */
    uint32_t rlbytes;

    /**
     * item is used to hold an item structure created after reading the command
     * line of set/add/replace commands, but before we finished reading the actual
     * data.
     */
    void* item;

    /* data for the mwrite state */
    std::vector<iovec> iov;
    /** number of elements used in iov[] */
    size_t iovused;

    /** The message list being used for transfer */
    std::vector<struct msghdr> msglist;
    /** element in msglist[] being transmitted now */
    size_t msgcurr;
    /** number of bytes in current msg */
    int msgbytes;

    /**
     * List of items we've reserved during the command (should call
     * item_release when transmit is complete)
     */
    std::vector<void*> reservedItems;

    /**
     * A vector of temporary allocations that should be freed when the
     * the connection is done sending all of the data. Use pushTempAlloc to
     * push a pointer to this list (must be allocated with malloc/calloc/strdup
     * etc.. will be freed by calling "free")
     */
    std::vector<char*> temp_alloc;

    /** True if the reply should not be sent (unless there is an error) */
    bool noreply;

    /**
     * If the client enabled the datatype support the response packet
     * will contain the datatype as set for the object
     */
    bool supports_datatype;

    /**
     * If the client enabled the mutation seqno feature each mutation
     * command will return the vbucket UUID and sequence number for the
     * mutation.
     */
    bool supports_mutation_extras;

    /**
     * The dynamic buffer is used to format output packets to be sent on
     * the wire.
     */
    DynamicBuffer dynamicBuffer;

    /**
     * The high resolution timer value for when we started executing the
     * current command.
     */
    hrtime_t start;

    /** the cas to return */
    uint64_t cas;

    /**
     * The status for the async io operation
     */
    ENGINE_ERROR_CODE aiostat;

    /**
     * Is this connection currently in an "ewouldblock" state?
     */
    bool ewouldblock;

    /**
     *  command-specific context - for use by command executors to maintain
     *  additional state while executing a command. For example
     *  a command may want to maintain some temporary state between retries
     *  due to engine returning EWOULDBLOCK.
     *
     *  Between each command this is deleted and reset to nullptr.
     */
    std::unique_ptr<CommandContext> commandContext;

    /**
     * The SSL context used by this connection (if enabled)
     */
    SslContext ssl;

    /**
     * Ensures that there is room for another struct iovec in a connection's
     * iov list.
     *
     * @throws std::bad_alloc
     */
    void ensureIovSpace();

    /**
     * Read data over the SSL connection
     *
     * @param dest where to store the data
     * @param nbytes the size of the destination buffer
     * @return the number of bytes read
     */
    int sslRead(char* dest, size_t nbytes);

    /**
     * Write data over the SSL stream
     *
     * @param src the source of the data
     * @param nbytes the number of bytes to send
     * @return the number of bytes written
     */
    int sslWrite(const char* src, size_t nbytes);

    /**
     * Handle the state for the ssl connection before the ssl connection
     * is fully established
     */
    int sslPreConnection();

    // Total number of bytes received on the network
    size_t totalRecv;
    // Total number of bytes sent to the network
    size_t totalSend;

    Cookie cookie;

    Datatype datatype;

    /**
     * It is possible to disable the SASL authentication for some
     * connections after they've been established.
     */
    bool saslAuthDisabled = false;
};

/*
    A connection on a pipe not a sockect

    This subclass doesn't do much, but should be expanded where exising
    logic in Connection breaks for a pipe.
*/
class PipeConnection : public McbpConnection {
public:
    PipeConnection() = delete;
    /*
     * Construct connection and set peername to be "pipe" and sockname to be
     * "pipe".
     */
    PipeConnection(SOCKET sfd, event_base* b);

    ~PipeConnection();

    virtual int sendmsg(struct msghdr* m) override;

    virtual int recv(char* dest, size_t nbytes) override;

    virtual bool isPipeConnection() override {
        return true;
    }
};
