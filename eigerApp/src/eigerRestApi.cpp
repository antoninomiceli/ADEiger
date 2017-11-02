#include "eigerRestApi.h"

#include <stdexcept>

#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <frozen.h>     // JSON parser

#include <epicsStdio.h>
#include <epicsThread.h>
#include <epicsTime.h>

#include <fcntl.h>

#define API_VERSION             "1.6.0"
#define EOL                     "\r\n"      // End of Line
#define EOL_LEN                 2           // End of Line Length
#define EOH                     EOL EOL     // End of Header
#define EOH_LEN                 (EOL_LEN*2) // End of Header Length

#define ID_STR                  "$id"
#define ID_LEN                  3

#define DATA_NATIVE             "application/json; charset=utf-8"
#define DATA_TIFF               "application/tiff"
#define DATA_HDF5               "application/hdf5"
#define DATA_HTML               "text/html"

#define MAX_HTTP_RETRIES        1
#define MAX_MESSAGE_SIZE        512
#define MAX_BUF_SIZE            256
#define MAX_JSON_TOKENS         100

#define DEFAULT_TIMEOUT_INIT    240
#define DEFAULT_TIMEOUT_ARM     120
#define DEFAULT_TIMEOUT_CONNECT 1

#define ERR_PREFIX  "EigerRestAPI"
#define ERR(msg) fprintf(stderr, ERR_PREFIX "::%s: %s\n", functionName, msg)

#define ERR_ARGS(fmt,...) fprintf(stderr, ERR_PREFIX "::%s: " fmt "\n", \
    functionName, __VA_ARGS__)

// Requests

#define REQUEST_GET\
    "GET %s%s HTTP/1.1" EOL \
    "Host: %s" EOL\
    "Content-Length: 0" EOL \
    "Accept: " DATA_NATIVE EOH

#define REQUEST_GET_FILE\
    "GET %s%s HTTP/1.1" EOL \
    "Host: %s" EOL\
    "Content-Length: 0" EOL \
    "Accept: %s" EOH

#define REQUEST_PUT\
    "PUT %s%s HTTP/1.1" EOL \
    "Host: %s" EOL\
    "Accept-Encoding: identity" EOL\
    "Content-Type: " DATA_NATIVE EOL \
    "Content-Length: %lu" EOH

#define REQUEST_HEAD\
    "HEAD %s%s HTTP/1.1" EOL\
    "Host: %s" EOH

#define REQUEST_DELETE\
    "DELETE %s%s HTTP/1.1" EOL\
    "Host: %s" EOH

using std::string;

// Static public members

const char *EigerRestAPI::sysStr [SSCount] = {
    "/detector/api/version",
    "/detector/api/"   API_VERSION "/config/",
    "/detector/api/"   API_VERSION "/status/",
    "/filewriter/api/" API_VERSION "/config/",
    "/filewriter/api/" API_VERSION "/status/",
    "/filewriter/api/" API_VERSION "/command/",
    "/detector/api/"   API_VERSION "/command/",
    "/data/",
    "/monitor/api/"    API_VERSION "/config/",
    "/monitor/api/"    API_VERSION "/status/",
    "/monitor/api/"    API_VERSION "/images/",
    "/stream/api/"     API_VERSION "/config/",
    "/stream/api/"     API_VERSION "/status/",
    "/system/api/"     API_VERSION "/command/",
};

static int parseSequenceId (const response_t *response, int *sequenceId)
{
    const char *functionName = "parseParamList";

    if(!response->contentLength)
    {
        ERR("no content to parse");
        return EXIT_FAILURE;
    }

    struct json_token tokens[MAX_JSON_TOKENS];
    int err = parse_json(response->content, response->contentLength, tokens,
            MAX_JSON_TOKENS);

    if(err < 0)
    {
        ERR("unable to parse response json");
        return EXIT_FAILURE;
    }

    if(tokens[0].type != JSON_TYPE_OBJECT)
    {
        ERR("unexpected token type");
        return EXIT_FAILURE;
    }

    struct json_token *seqIdToken = find_json_token(tokens, "sequence id");
    if(!seqIdToken)
    {
        seqIdToken = find_json_token(tokens, "series id");
        if(!seqIdToken)
        {
            ERR("unable to find 'series id' or 'sequence id' token");
            return EXIT_FAILURE;
        }
    }

    if(sscanf(seqIdToken->ptr, "%d", sequenceId) != 1)
    {
        ERR("unable to parse 'sequence_id' token");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int EigerRestAPI::buildMasterName (const char *pattern, int seqId, char *buf, size_t bufSize)
{
    const char *idStr = strstr(pattern, ID_STR);

    if(idStr)
    {
        int prefixLen = idStr - pattern;
        epicsSnprintf(buf, bufSize, "%.*s%d%s_master.h5", prefixLen, pattern, seqId,
                pattern+prefixLen+ID_LEN);
    }
    else
        epicsSnprintf(buf, bufSize, "%s_master.h5", pattern);

    return EXIT_SUCCESS;
}

int EigerRestAPI::buildDataName (int n, const char *pattern, int seqId, char *buf, size_t bufSize)
{
    const char *idStr = strstr(pattern, ID_STR);

    if(idStr)
    {
        int prefixLen = idStr - pattern;
        epicsSnprintf(buf, bufSize, "%.*s%d%s_data_%06d.h5", prefixLen, pattern, seqId,
                pattern+prefixLen+ID_LEN, n);
    }
    else
        epicsSnprintf(buf, bufSize, "%s_data_%06d.h5", pattern, n);

    return EXIT_SUCCESS;
}

// Public members

EigerRestAPI::EigerRestAPI (string const & hostname, int port, size_t numSockets) :
    RestAPI(hostname, port, numSockets)
{
    memset(&mAddress, 0, sizeof(mAddress));

    if(hostToIPAddr(mHostname.c_str(), &mAddress.sin_addr))
        throw std::runtime_error("invalid hostname");

    mAddress.sin_family = AF_INET;
    mAddress.sin_port = htons(port);

    for(size_t i = 0; i < mNumSockets; ++i)
    {
        mSockets[i].closed = true;
        mSockets[i].fd = -1;
        mSockets[i].retries = 0;
    }
}

int EigerRestAPI::initialize (void)
{
    return put(sysStr[SSCommand], "initialize", "", NULL, DEFAULT_TIMEOUT_INIT);
}

int EigerRestAPI::arm (int *sequenceId)
{
    const char *functionName = "arm";

    request_t request = {};
    char requestBuf[MAX_MESSAGE_SIZE];
    request.data      = requestBuf;
    request.dataLen   = sizeof(requestBuf);
    request.actualLen = epicsSnprintf(request.data, request.dataLen,
            REQUEST_PUT, sysStr[SSCommand], "arm", mHostname.c_str(), 0lu);

    response_t response = {};
    char responseBuf[MAX_MESSAGE_SIZE];
    response.data    = responseBuf;
    response.dataLen = sizeof(responseBuf);

    if(doRequest(&request, &response, DEFAULT_TIMEOUT_ARM))
    {
        ERR("[param=arm] request failed");
        return EXIT_FAILURE;
    }

    if(response.code != 200)
    {
        ERR_ARGS("[param=arm] server returned error code %d", response.code);
        return EXIT_FAILURE;
    }

    return sequenceId ? parseSequenceId(&response, sequenceId) : EXIT_SUCCESS;
}

int EigerRestAPI::trigger (int timeout, double exposure)
{
    // Trigger for INTS mode
    if(!exposure)
        return put(sysStr[SSCommand], "trigger", "", NULL, timeout);

    // Tigger for INTE mode
    // putDouble should block for the whole exposure duration, but it doesn't
    // (Eiger's fault)
    char exposureStr[MAX_BUF_SIZE];
    epicsSnprintf(exposureStr, sizeof(exposureStr), "%lf", exposure);

    epicsTimeStamp start, end;
    epicsTimeGetCurrent(&start);
    if(put(sysStr[SSCommand], "trigger", exposureStr, NULL, timeout))
        return EXIT_FAILURE;
    epicsTimeGetCurrent(&end);

    double diff = epicsTimeDiffInSeconds(&end, &start);
    if(diff < exposure)
        epicsThreadSleep(exposure - diff);

    return EXIT_SUCCESS;
}

int EigerRestAPI::disarm (void)
{
    return put(sysStr[SSCommand], "disarm");
}

int EigerRestAPI::cancel (void)
{
    return put(sysStr[SSCommand], "cancel");
}

int EigerRestAPI::abort (void)
{
    return put(sysStr[SSCommand], "abort");
}

int EigerRestAPI::wait (void)
{
    return put(sysStr[SSCommand], "wait", "", NULL, -1);
}

int EigerRestAPI::statusUpdate (void)
{
    return put(sysStr[SSCommand], "status_update");
}

int EigerRestAPI::getFileSize (const char *filename, size_t *size)
{
    const char *functionName = "getFileSize";

    request_t request = {};
    char requestBuf[MAX_MESSAGE_SIZE];
    request.data      = requestBuf;
    request.dataLen   = sizeof(requestBuf);
    request.actualLen = epicsSnprintf(request.data, request.dataLen,
            REQUEST_HEAD, sysStr[SSData], filename, mHostname.c_str());

    response_t response = {};
    char responseBuf[MAX_MESSAGE_SIZE];
    response.data    = responseBuf;
    response.dataLen = sizeof(responseBuf);

    if(doRequest(&request, &response))
    {
        ERR_ARGS("[file=%s] HEAD request failed", filename);
        return EXIT_FAILURE;
    }

    if(response.code != 200)
    {
        ERR_ARGS("[file=%s] server returned error code %d", filename,
                response.code);
        return EXIT_FAILURE;
    }

    *size = response.contentLength;
    return EXIT_SUCCESS;
}

int EigerRestAPI::waitFile (const char *filename, double timeout)
{
    const char *functionName = "waitFile";

    epicsTimeStamp start, now;

    request_t request = {};
    char requestBuf[MAX_MESSAGE_SIZE];
    request.data      = requestBuf;
    request.dataLen   = sizeof(requestBuf);
    request.actualLen = epicsSnprintf(request.data, request.dataLen,
            REQUEST_HEAD, sysStr[SSData], filename, mHostname.c_str());

    response_t response = {};
    char responseBuf[MAX_MESSAGE_SIZE];
    response.data    = responseBuf;
    response.dataLen = sizeof(responseBuf);

    epicsTimeGetCurrent(&start);

    do
    {
        if(doRequest(&request, &response))
        {
            ERR_ARGS("[file=%s] HEAD request failed", filename);
            return EXIT_FAILURE;
        }

        if(response.code == 200)
            return EXIT_SUCCESS;

        if(response.code != 404)
        {
            ERR_ARGS("[file=%s] server returned error code %d", filename,
                    response.code);
            return EXIT_FAILURE;
        }

        epicsTimeGetCurrent(&now);
    }while(epicsTimeDiffInSeconds(&now, &start) < timeout);

    //ERR_ARGS("timeout waiting for file %s", filename);
    return EXIT_FAILURE;
}

int EigerRestAPI::getFile (const char *filename, char **buf, size_t *bufSize)
{
    return getBlob(SSData, filename, buf, bufSize, DATA_HDF5);
}

int EigerRestAPI::deleteFile (const char *filename)
{
    const char *functionName = "deleteFile";

    request_t request = {};
    char requestBuf[MAX_MESSAGE_SIZE];
    request.data      = requestBuf;
    request.dataLen   = sizeof(requestBuf);
    request.actualLen = epicsSnprintf(request.data, request.dataLen,
            REQUEST_DELETE, sysStr[SSData], filename, mHostname.c_str());

    response_t response = {};
    char responseBuf[MAX_MESSAGE_SIZE];
    response.data    = responseBuf;
    response.dataLen = sizeof(responseBuf);

    if(doRequest(&request, &response))
    {
        ERR_ARGS("[file=%s] DELETE request failed", filename);
        return EXIT_FAILURE;
    }

    if(response.code != 204)
    {
        ERR_ARGS("[file=%s] DELETE returned code %d", filename, response.code);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int EigerRestAPI::getMonitorImage (char **buf, size_t *bufSize, size_t timeout)
{
    char param[MAX_BUF_SIZE];
    epicsSnprintf(param, sizeof(param), "monitor?timeout=%lu", timeout);
    return getBlob(SSMonImages, param, buf, bufSize, DATA_TIFF);
}

// Private members

int EigerRestAPI::getBlob (sys_t sys, const char *name, char **buf, size_t *bufSize,
        const char *accept)
{
    const char *functionName = "getBlob";
    int status = EXIT_SUCCESS;
    int received;
    size_t remaining;
    char *bufp;

    request_t request = {};
    char requestBuf[MAX_MESSAGE_SIZE];
    request.data      = requestBuf;
    request.dataLen   = sizeof(requestBuf);
    request.actualLen = epicsSnprintf(request.data, request.dataLen,
            REQUEST_GET_FILE, sysStr[sys], name, mHostname.c_str(), accept);

    response_t response = {};
    char responseBuf[MAX_MESSAGE_SIZE];
    response.data    = responseBuf;
    response.dataLen = sizeof(responseBuf);

    socket_t *s = NULL;
    bool gotSocket = false;

    for(size_t i = 0; i < mNumSockets && !gotSocket; ++i)
    {
        s = &mSockets[i];
        if(s->mutex.tryLock())
            gotSocket = true;
    }

    if(!gotSocket)
    {
        ERR("no available socket");
        status = EXIT_FAILURE;
        goto end;
    }

    if(s->closed)
    {
        if(connect(s))
        {
            ERR("failed to reconnect socket");
            status = EXIT_FAILURE;
            goto end;
        }
    }

    // Send the request
    if(send(s->fd, request.data, request.actualLen, 0) < 0)
    {
        if(s->retries++ < MAX_HTTP_RETRIES)
            goto retry;
        else
        {
            ERR("failed to send");
            status = EXIT_FAILURE;
            goto end;
        }
    }

    // Receive the first part of the response (header and some content)
    if((received = recv(s->fd, response.data, response.dataLen, 0)) <= 0)
    {
        if(s->retries++ < MAX_HTTP_RETRIES)
            goto retry;
        else
        {
            ERR_ARGS("[sys=%d file=%s] failed to receive first part", sys, name);
            status = EXIT_FAILURE;
            goto end;
        }
    }

    if((status = parseHeader(&response)))
    {
        ERR_ARGS("[sys=%d file=%s] underlying parseResponse failed", sys, name);
        goto end;
    }

    if(response.code != 200)
    {
        if(sys != SSMonImages)
            ERR_ARGS("[sys=%d file=%s] file not found", sys, name);
        status = EXIT_FAILURE;
        goto end;
    }

    // Create the receive buffer and copy over what we already received
    *buf = (char*)malloc(response.contentLength);
    if(!*buf)
    {
        ERR_ARGS("[sys=%d file=%s] malloc(%lu) failed", sys, name, response.contentLength);
        status = EXIT_FAILURE;
        goto end;
    }

    // Assume that we got the whole header
    *bufSize = received - response.headerLen;
    memcpy(*buf, response.content, *bufSize);

    // Get the rest of the content (MSG_WAITALL can fail!)
    remaining = response.contentLength - *bufSize;
    bufp = *buf + *bufSize;

    while(remaining)
    {
        received = recv(s->fd, bufp, remaining, MSG_WAITALL);

        if(received <= 0)
        {
            free(*buf);
            *buf = NULL;
            *bufSize = 0;

            if(s->retries++ < MAX_HTTP_RETRIES)
                goto retry;
            else
            {
                ERR_ARGS("[sys=%d file=%s] failed to receive second part", sys, name);
                status = EXIT_FAILURE;
                goto end;
            }
        }

        remaining -= received;
        bufp += received;
    }

    *bufSize = response.contentLength;

    if(response.reconnect)
    {
        close(s->fd);
        s->closed = true;
    }

end:
    s->retries = 0;
    s->mutex.unlock();
    return status;

retry:
    close(s->fd);
    s->closed = true;
    s->mutex.unlock();
    return getBlob(sys, name, buf, bufSize, accept);
}

int EigerRestAPI::lookupAccessMode(
        std::string subSystem, rest_access_mode_t &accessMode)
{
    long ssEnum = std::distance(
            sysStr, std::find(sysStr, sysStr + SSCount, subSystem));
    switch(ssEnum)
    {
        case SSCommand:
        case SSFWCommand:
        case SSSysCommand:
            accessMode = REST_ACC_WO;
            return EXIT_SUCCESS;
        case SSDetStatus:
        case SSFWStatus:
        case SSMonStatus:
        case SSStreamStatus:
            accessMode = REST_ACC_RO;
            return EXIT_SUCCESS;
        default:
            return EXIT_FAILURE;
    }
}
