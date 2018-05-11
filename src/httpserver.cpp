// Copyright (c) 2015-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <httpserver.h>

#include <netaddress.h>
#include <compat.h>
#include <utils.h>
#include <sync.h>

#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <future>

#include <queue>

#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>
#include <event2/event.h>
#include <event2/http.h>

#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
#ifdef _XOPEN_SOURCE_EXTENDED
#include <arpa/inet.h>
#endif
#endif

#define MAKE_RAII(type) \
/* deleter */\
struct type##_deleter {\
    void operator()(struct type* ob) {\
        type##_free(ob);\
    }\
};\
/* unique ptr typedef */\
typedef std::unique_ptr<struct type, type##_deleter> raii_##type

MAKE_RAII(event_base);
MAKE_RAII(event);
MAKE_RAII(evhttp);
MAKE_RAII(evhttp_request);
MAKE_RAII(evhttp_connection);

inline raii_event_base obtain_event_base() {
    auto result = raii_event_base(event_base_new());
    if (!result.get())
        throw std::runtime_error("cannot create event_base");
    return result;
}

inline raii_event obtain_event(struct event_base* base, evutil_socket_t s, short events, event_callback_fn cb, void* arg) {
    return raii_event(event_new(base, s, events, cb, arg));
}

inline raii_evhttp obtain_evhttp(struct event_base* base) {
    return raii_evhttp(evhttp_new(base));
}

inline raii_evhttp_request obtain_evhttp_request(void(*cb)(struct evhttp_request *, void *), void *arg) {
    return raii_evhttp_request(evhttp_request_new(cb, arg));
}

inline raii_evhttp_connection obtain_evhttp_connection_base(struct event_base* base, std::string host, uint16_t port) {
    auto result = raii_evhttp_connection(evhttp_connection_base_new(base, nullptr, host.c_str(), port));
    if (!result.get())
        throw std::runtime_error("create connection failed");
    return result;
}

static const unsigned int MAX_SIZE = 0x02000000;

void RenameThread(const char* name)
{
#if defined(PR_SET_NAME)
    // Only the first 15 characters are used (16 - NUL terminator)
    ::prctl(PR_SET_NAME, name, 0, 0, 0);
#elif (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
    pthread_set_name_np(pthread_self(), name);

#elif defined(MAC_OSX)
    pthread_setname_np(name);
#else
    // Prevent warnings for unused parameters...
    (void)name;
#endif
}

static bool ParsePrechecks(const std::string& str)
{
    if (str.empty()) // No empty string allowed
        return false;
    if (str.size() >= 1 && (isspace(str[0]) || isspace(str[str.size()-1]))) // No padding allowed
        return false;
    if (str.size() != strlen(str.c_str())) // No embedded NUL characters allowed
        return false;
    return true;
}

bool ParseInt32(const std::string& str, int32_t *out)
{
    if (!ParsePrechecks(str))
        return false;
    char *endp = nullptr;
    errno = 0; // strtol will not set errno if valid
    long int n = strtol(str.c_str(), &endp, 10);
    if(out) *out = (int32_t)n;
    // Note that strtol returns a *long int*, so even if strtol doesn't report an over/underflow
    // we still have to check that the returned value is within the range of an *int32_t*. On 64-bit
    // platforms the size of these types may be different.
    return endp && *endp == 0 && !errno &&
        n >= std::numeric_limits<int32_t>::min() &&
        n <= std::numeric_limits<int32_t>::max();
}

void SplitHostPort(std::string in, int &portOut, std::string &hostOut) {
    size_t colon = in.find_last_of(':');
    // if a : is found, and it either follows a [...], or no other : is in the string, treat it as port separator
    bool fHaveColon = colon != in.npos;
    bool fBracketed = fHaveColon && (in[0]=='[' && in[colon-1]==']'); // if there is a colon, and in[0]=='[', colon is not 0, so in[colon-1] is safe
    bool fMultiColon = fHaveColon && (in.find_last_of(':',colon-1) != in.npos);
    if (fHaveColon && (colon==0 || fBracketed || !fMultiColon)) {
        int32_t n;
        if (ParseInt32(in.substr(colon + 1), &n) && n > 0 && n < 0x10000) {
            in = in.substr(0, colon);
            portOut = n;
        }
    }
    if (in.size()>0 && in[0] == '[' && in[in.size()-1] == ']')
        hostOut = in.substr(1, in.size()-2);
    else
        hostOut = in;
}

/** Maximum size of http request (request line + headers) */
static const size_t MAX_HEADERS_SIZE = 8192;

/** HTTP request work item */
class HTTPWorkItem final : public HTTPClosure
{
public:
    HTTPWorkItem(std::unique_ptr<HTTPRequest> _req, const std::string &_path, const HTTPRequestHandler& _func):
        req(std::move(_req)), path(_path), func(_func)
    {
    }
    void operator()() override
    {
        func(req.get(), path);
    }

    std::unique_ptr<HTTPRequest> req;

private:
    std::string path;
    HTTPRequestHandler func;
};

/** Simple work queue for distributing work over multiple threads.
 * Work items are simply callable objects.
 */
template <typename WorkItem>
class WorkQueue
{
private:
    /** Mutex protects entire object */
    std::mutex cs;
    std::condition_variable cond;
    std::deque<std::unique_ptr<WorkItem>> queue;
    bool running;
    size_t maxDepth;

public:
    explicit WorkQueue(size_t _maxDepth) : running(true),
                                 maxDepth(_maxDepth)
    {
    }
    /** Precondition: worker threads have all stopped (they have been joined).
     */
    ~WorkQueue()
    {
    }
    /** Enqueue a work item */
    bool Enqueue(WorkItem* item)
    {
        std::unique_lock<std::mutex> lock(cs);
        if (queue.size() >= maxDepth) {
            return false;
        }
        queue.emplace_back(std::unique_ptr<WorkItem>(item));
        cond.notify_one();
        return true;
    }
    /** Thread function */
    void Run()
    {
        while (true) {
            std::unique_ptr<WorkItem> i;
            {
                std::unique_lock<std::mutex> lock(cs);
                while (running && queue.empty())
                    cond.wait(lock);
                if (!running)
                    break;
                i = std::move(queue.front());
                queue.pop_front();
            }
            (*i)();
        }
    }
    /** Interrupt and exit loops */
    void Interrupt()
    {
        std::unique_lock<std::mutex> lock(cs);
        running = false;
        cond.notify_all();
    }
};

struct HTTPPathHandler
{
    HTTPPathHandler() {}
    HTTPPathHandler(std::string _prefix, bool _exactMatch, HTTPRequestHandler _handler):
        prefix(_prefix), exactMatch(_exactMatch), handler(_handler)
    {
    }
    std::string prefix;
    bool exactMatch;
    HTTPRequestHandler handler;
};

/** HTTP module state */

//! libevent event loop
static struct event_base* eventBase = nullptr;
//! HTTP server
struct evhttp* eventHTTP = nullptr;
//! List of addresses to allow RPC connections from
static std::vector<std::string> rpc_allow_addresses;
//! Work queue for handling longer requests off the event loop thread
static WorkQueue<HTTPClosure>* workQueue = nullptr;
//! Handlers for (sub)paths
std::vector<HTTPPathHandler> pathHandlers;
//! Bound listening sockets
std::vector<evhttp_bound_socket *> boundSockets;

/** Check if a network address is allowed to access the HTTP server */
static bool ClientAllowed(const std::string& netaddr)
{
    if (netaddr == "") return false;
    for(const std::string& ip : rpc_allow_addresses) {
        if (netaddr == ip) return true;
    }
    return false;
}

/** Initialize ACL list for HTTP server */
static bool InitHTTPAllowList()
{
    rpc_allow_addresses.push_back("127.0.0.1");
    rpc_allow_addresses.push_back("::1");
    return true;
}

/** HTTP request method as string - use for logging only */
static std::string RequestMethodString(HTTPRequest::RequestMethod m)
{
    switch (m) {
    case HTTPRequest::GET:
        return "GET";
        break;
    case HTTPRequest::POST:
        return "POST";
        break;
    case HTTPRequest::HEAD:
        return "HEAD";
        break;
    case HTTPRequest::PUT:
        return "PUT";
        break;
    default:
        return "unknown";
    }
}

/** HTTP request callback */
static void http_request_cb(struct evhttp_request* req, void* arg)
{
    // Disable reading to work around a libevent bug, fixed in 2.2.0.
    if (event_get_version_number() >= 0x02010600 && event_get_version_number() < 0x02020001) {
        evhttp_connection* conn = evhttp_request_get_connection(req);
        if (conn) {
            bufferevent* bev = evhttp_connection_get_bufferevent(conn);
            if (bev) {
                bufferevent_disable(bev, EV_READ);
            }
        }
    }
    std::unique_ptr<HTTPRequest> hreq(new HTTPRequest(req));

    LogPrintf("Received a %s request for %s from %s\n",
             RequestMethodString(hreq->GetRequestMethod()), hreq->GetURI(), hreq->GetPeer());

    // Early address-based allow check
    if (!ClientAllowed(hreq->GetPeer())) {
        hreq->WriteReply(HTTP_FORBIDDEN);
        return;
    }

    // Early reject unknown HTTP methods
    if (hreq->GetRequestMethod() == HTTPRequest::UNKNOWN) {
        hreq->WriteReply(HTTP_BADMETHOD);
        return;
    }

    // Find registered handler for prefix
    std::string strURI = hreq->GetURI();
    std::string path;
    std::vector<HTTPPathHandler>::const_iterator i = pathHandlers.begin();
    std::vector<HTTPPathHandler>::const_iterator iend = pathHandlers.end();
    for (; i != iend; ++i) {
        bool match = false;
        if (i->exactMatch)
            match = (strURI == i->prefix);
        else
            match = (strURI.substr(0, i->prefix.size()) == i->prefix);
        if (match) {
            path = strURI.substr(i->prefix.size());
            break;
        }
    }

    // Dispatch to worker thread
    if (i != iend) {
        std::unique_ptr<HTTPWorkItem> item(new HTTPWorkItem(std::move(hreq), path, i->handler));
        assert(workQueue);
        if (workQueue->Enqueue(item.get()))
            item.release(); /* if true, queue took ownership */
        else {
            LogPrintf("WARNING: request rejected because http work queue depth exceeded, it can be increased with the -rpcworkqueue= setting\n");
            item->req->WriteReply(HTTP_INTERNAL, "Work queue depth exceeded");
        }
    } else {
        hreq->WriteReply(HTTP_NOTFOUND);
    }
}

/** Callback to reject HTTP requests after shutdown. */
static void http_reject_request_cb(struct evhttp_request* req, void*)
{
    LogPrintf("Rejecting request while shutting down\n");
    evhttp_send_error(req, HTTP_SERVUNAVAIL, nullptr);
}

/** Event dispatcher thread */
static bool ThreadHTTP(struct event_base* base, struct evhttp* http)
{
    RenameThread("bitcoin-http");
    LogPrintf("Entering http event loop\n");
    event_base_dispatch(base);
    // Event loop will be interrupted by InterruptHTTPServer()
    LogPrintf("Exited http event loop\n");
    return event_base_got_break(base) == 0;
}

/** Bind HTTP server to specified addresses */
static bool HTTPBindAddresses(struct evhttp* http)
{
    int defaultPort = g_args.GetArg("-rpcport", 5442);
    std::vector<std::pair<std::string, uint16_t> > endpoints;

    // Determine what addresses to bind to
    if (!g_args.IsArgSet("-rpcallowip")) { // Default to loopback if not allowing external IPs
        endpoints.push_back(std::make_pair("::1", defaultPort));
        endpoints.push_back(std::make_pair("127.0.0.1", defaultPort));
        if (g_args.IsArgSet("-rpcbind")) {
            LogPrintf("WARNING: option -rpcbind was ignored because -rpcallowip was not specified, refusing to allow everyone to connect\n");
        }
    } else if (g_args.IsArgSet("-rpcbind")) { // Specific bind address
        for (const std::string& strRPCBind : g_args.GetArgs("-rpcbind")) {
            int port = defaultPort;
            std::string host;
            SplitHostPort(strRPCBind, port, host);
            endpoints.push_back(std::make_pair(host, port));
        }
    } else { // No specific bind address specified, bind to any
        endpoints.push_back(std::make_pair("::", defaultPort));
        endpoints.push_back(std::make_pair("0.0.0.0", defaultPort));
    }

    // Bind addresses
    for (std::vector<std::pair<std::string, uint16_t> >::iterator i = endpoints.begin(); i != endpoints.end(); ++i) {
        LogPrintf("Binding RPC on address %s port %i\n", i->first, i->second);
        evhttp_bound_socket *bind_handle = evhttp_bind_socket_with_handle(http, i->first.empty() ? nullptr : i->first.c_str(), i->second);
        if (bind_handle) {
            boundSockets.push_back(bind_handle);
        } else {
            LogPrintf("Binding RPC on address %s port %i failed.\n", i->first, i->second);
        }
    }
    return !boundSockets.empty();
}

/** Simple wrapper to set thread name and run work queue */
static void HTTPWorkQueueRun(WorkQueue<HTTPClosure>* queue)
{
    RenameThread("bitcoin-httpworker");
    queue->Run();
}

/** libevent event log callback */
static void libevent_log_cb(int severity, const char *msg)
{
#ifndef EVENT_LOG_WARN
// EVENT_LOG_WARN was added in 2.0.19; but before then _EVENT_LOG_WARN existed.
# define EVENT_LOG_WARN _EVENT_LOG_WARN
#endif
    if (severity >= EVENT_LOG_WARN) // Log warn messages and higher without debug category
        LogPrintf("libevent: %s\n", msg);
    else
        LogPrintf("libevent: %s\n", msg);
}

bool InitHTTPServer()
{
    if (!InitHTTPAllowList())
        return false;

    // Redirect libevent's logging to our own log
    event_set_log_callback(&libevent_log_cb);
    // Update libevent's log handling. Returns false if our version of
    // libevent doesn't support debug logging, in which case we should
    // clear the BCLog::LIBEVENT flag.
    /*
    if (!UpdateHTTPServerLogging(g_logger->WillLogCategory(BCLog::LIBEVENT))) {
        g_logger->DisableCategory(BCLog::LIBEVENT);
    }
    */

#ifdef WIN32
    evthread_use_windows_threads();
#else
    evthread_use_pthreads();
#endif

    raii_event_base base_ctr = obtain_event_base();

    /* Create a new evhttp object to handle requests. */
    raii_evhttp http_ctr = obtain_evhttp(base_ctr.get());
    struct evhttp* http = http_ctr.get();
    if (!http) {
        LogPrintf("couldn't create evhttp. Exiting.\n");
        return false;
    }

    evhttp_set_timeout(http, g_args.GetArg("-rpcservertimeout", DEFAULT_HTTP_SERVER_TIMEOUT));
    evhttp_set_max_headers_size(http, MAX_HEADERS_SIZE);
    evhttp_set_max_body_size(http, MAX_SIZE);
    evhttp_set_gencb(http, http_request_cb, nullptr);

    if (!HTTPBindAddresses(http)) {
        LogPrintf("Unable to bind any endpoint for RPC server\n");
        return false;
    }

    LogPrintf("Initialized HTTP server\n");
    int workQueueDepth = std::max((long)g_args.GetArg("-rpcworkqueue", DEFAULT_HTTP_WORKQUEUE), 1L);
    LogPrintf("HTTP: creating work queue of depth %d\n", workQueueDepth);

    workQueue = new WorkQueue<HTTPClosure>(workQueueDepth);
    // transfer ownership to eventBase/HTTP via .release()
    eventBase = base_ctr.release();
    eventHTTP = http_ctr.release();
    return true;
}

bool UpdateHTTPServerLogging(bool enable) {
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
    if (enable) {
        event_enable_debug_logging(EVENT_DBG_ALL);
    } else {
        event_enable_debug_logging(EVENT_DBG_NONE);
    }
    return true;
#else
    // Can't update libevent logging if version < 02010100
    return false;
#endif
}

std::thread threadHTTP;
std::future<bool> threadResult;
static std::vector<std::thread> g_thread_http_workers;

bool StartHTTPServer()
{
    LogPrintf("Starting HTTP server\n");
    int rpcThreads = std::max((long)g_args.GetArg("-rpcthreads", DEFAULT_HTTP_THREADS), 1L);
    LogPrintf("HTTP: starting %d worker threads\n", rpcThreads);
    std::packaged_task<bool(event_base*, evhttp*)> task(ThreadHTTP);
    threadResult = task.get_future();
    threadHTTP = std::thread(std::move(task), eventBase, eventHTTP);

    for (int i = 0; i < rpcThreads; i++) {
        g_thread_http_workers.emplace_back(HTTPWorkQueueRun, workQueue);
    }
    return true;
}

void InterruptHTTPServer()
{
    LogPrintf("Interrupting HTTP server\n");
    if (eventHTTP) {
        // Unlisten sockets
        for (evhttp_bound_socket *socket : boundSockets) {
            evhttp_del_accept_socket(eventHTTP, socket);
        }
        // Reject requests on current connections
        evhttp_set_gencb(eventHTTP, http_reject_request_cb, nullptr);
    }
    if (workQueue)
        workQueue->Interrupt();
}

void StopHTTPServer()
{
    LogPrintf("Stopping HTTP server\n");
    if (workQueue) {
        workQueue->Interrupt();
        LogPrintf("Waiting for HTTP worker threads to exit\n");
        for (auto& thread: g_thread_http_workers) {
            thread.join();
        }
        g_thread_http_workers.clear();
        delete workQueue;
        workQueue = nullptr;
    }
    if (eventBase) {
        LogPrintf("Waiting for HTTP event thread to exit\n");
        // Exit the event loop as soon as there are no active events.
        event_base_loopexit(eventBase, nullptr);
        // Give event loop a few seconds to exit (to send back last RPC responses), then break it
        // Before this was solved with event_base_loopexit, but that didn't work as expected in
        // at least libevent 2.0.21 and always introduced a delay. In libevent
        // master that appears to be solved, so in the future that solution
        // could be used again (if desirable).
        // (see discussion in https://github.com/bitcoin/bitcoin/pull/6990)
        if (threadResult.valid() && threadResult.wait_for(std::chrono::milliseconds(2000)) == std::future_status::timeout) {
            LogPrintf("HTTP event loop did not exit within allotted time, sending loopbreak\n");
            event_base_loopbreak(eventBase);
        }
        threadHTTP.join();
    }
    if (eventHTTP) {
        evhttp_free(eventHTTP);
        eventHTTP = nullptr;
    }
    if (eventBase) {
        event_base_free(eventBase);
        eventBase = nullptr;
    }
    LogPrintf("Stopped HTTP server\n");
}

struct event_base* EventBase()
{
    return eventBase;
}

static void httpevent_callback_fn(evutil_socket_t, short, void* data)
{
    // Static handler: simply call inner handler
    HTTPEvent *self = static_cast<HTTPEvent*>(data);
    self->handler();
    if (self->deleteWhenTriggered)
        delete self;
}

HTTPEvent::HTTPEvent(struct event_base* base, bool _deleteWhenTriggered, const std::function<void(void)>& _handler):
    deleteWhenTriggered(_deleteWhenTriggered), handler(_handler)
{
    ev = event_new(base, -1, 0, httpevent_callback_fn, this);
    assert(ev);
}
HTTPEvent::~HTTPEvent()
{
    event_free(ev);
}
void HTTPEvent::trigger(struct timeval* tv)
{
    if (tv == nullptr)
        event_active(ev, 0, 0); // immediately trigger event in main thread
    else
        evtimer_add(ev, tv); // trigger after timeval passed
}
HTTPRequest::HTTPRequest(struct evhttp_request* _req) : req(_req),
                                                       replySent(false)
{
}
HTTPRequest::~HTTPRequest()
{
    if (!replySent) {
        // Keep track of whether reply was sent to avoid request leaks
        LogPrintf("%s: Unhandled request\n", __func__);
        WriteReply(HTTP_INTERNAL, "Unhandled request");
    }
    // evhttpd cleans up the request, as long as a reply was sent.
}

std::pair<bool, std::string> HTTPRequest::GetHeader(const std::string& hdr)
{
    const struct evkeyvalq* headers = evhttp_request_get_input_headers(req);
    assert(headers);
    const char* val = evhttp_find_header(headers, hdr.c_str());
    if (val)
        return std::make_pair(true, val);
    else
        return std::make_pair(false, "");
}

std::string HTTPRequest::ReadBody()
{
    struct evbuffer* buf = evhttp_request_get_input_buffer(req);
    if (!buf)
        return "";
    size_t size = evbuffer_get_length(buf);
    /** Trivial implementation: if this is ever a performance bottleneck,
     * internal copying can be avoided in multi-segment buffers by using
     * evbuffer_peek and an awkward loop. Though in that case, it'd be even
     * better to not copy into an intermediate string but use a stream
     * abstraction to consume the evbuffer on the fly in the parsing algorithm.
     */
    const char* data = (const char*)evbuffer_pullup(buf, size);
    if (!data) // returns nullptr in case of empty buffer
        return "";
    std::string rv(data, size);
    evbuffer_drain(buf, size);
    return rv;
}

void HTTPRequest::WriteHeader(const std::string& hdr, const std::string& value)
{
    struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
    assert(headers);
    evhttp_add_header(headers, hdr.c_str(), value.c_str());
}

/** Closure sent to main thread to request a reply to be sent to
 * a HTTP request.
 * Replies must be sent in the main loop in the main http thread,
 * this cannot be done from worker threads.
 */
void HTTPRequest::WriteReply(int nStatus, const std::string& strReply)
{
    assert(!replySent && req);
    // Send event to main http thread to send reply message
    struct evbuffer* evb = evhttp_request_get_output_buffer(req);
    assert(evb);
    evbuffer_add(evb, strReply.data(), strReply.size());
    auto req_copy = req;
    HTTPEvent* ev = new HTTPEvent(eventBase, true, [req_copy, nStatus]{
        evhttp_send_reply(req_copy, nStatus, nullptr, nullptr);
        // Re-enable reading from the socket. This is the second part of the libevent
        // workaround above.
        if (event_get_version_number() >= 0x02010600 && event_get_version_number() < 0x02020001) {
            evhttp_connection* conn = evhttp_request_get_connection(req_copy);
            if (conn) {
                bufferevent* bev = evhttp_connection_get_bufferevent(conn);
                if (bev) {
                    bufferevent_enable(bev, EV_READ | EV_WRITE);
                }
            }
        }
    });
    ev->trigger(nullptr);
    replySent = true;
    req = nullptr; // transferred back to main thread
}

std::string HTTPRequest::GetPeer()
{
    evhttp_connection* con = evhttp_request_get_connection(req);
    if (con) {
        // evhttp retains ownership over returned address string
        const char* address = "";
        uint16_t port = 0;
        evhttp_connection_get_peer(con, (char**)&address, &port);
        return std::string(address);
    }
    return "";
}

std::string HTTPRequest::GetURI()
{
    return evhttp_request_get_uri(req);
}

HTTPRequest::RequestMethod HTTPRequest::GetRequestMethod()
{
    switch (evhttp_request_get_command(req)) {
    case EVHTTP_REQ_GET:
        return GET;
        break;
    case EVHTTP_REQ_POST:
        return POST;
        break;
    case EVHTTP_REQ_HEAD:
        return HEAD;
        break;
    case EVHTTP_REQ_PUT:
        return PUT;
        break;
    default:
        return UNKNOWN;
        break;
    }
}

void RegisterHTTPHandler(const std::string &prefix, bool exactMatch, const HTTPRequestHandler &handler)
{
    LogPrintf("Registering HTTP handler for %s (exactmatch %d)\n", prefix, exactMatch);
    pathHandlers.push_back(HTTPPathHandler(prefix, exactMatch, handler));
}

void UnregisterHTTPHandler(const std::string &prefix, bool exactMatch)
{
    std::vector<HTTPPathHandler>::iterator i = pathHandlers.begin();
    std::vector<HTTPPathHandler>::iterator iend = pathHandlers.end();
    for (; i != iend; ++i)
        if (i->prefix == prefix && i->exactMatch == exactMatch)
            break;
    if (i != iend)
    {
        LogPrintf("Unregistering HTTP handler for %s (exactmatch %d)\n", prefix, exactMatch);
        pathHandlers.erase(i);
    }
}

std::string urlDecode(const std::string &urlEncoded) {
    std::string res;
    if (!urlEncoded.empty()) {
        char *decoded = evhttp_uridecode(urlEncoded.c_str(), false, nullptr);
        if (decoded) {
            res = std::string(decoded);
            free(decoded);
        }
    }
    return res;
}
