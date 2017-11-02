#ifndef EIGER_REST_API_H
#define EIGER_REST_API_H

#include <map>
#include <string>
#include <epicsMutex.h>
#include <osiSock.h>

#include "restApi.h"
#include "restParam.h"

// Subsystems
typedef enum
{
    SSAPIVersion,
    SSDetConfig,
    SSDetStatus,
    SSFWConfig,
    SSFWStatus,
    SSFWCommand,
    SSCommand,
    SSData,
    SSMonConfig,
    SSMonStatus,
    SSMonImages,
    SSStreamConfig,
    SSStreamStatus,
    SSSysCommand,

    SSCount,
} sys_t;

class EigerRestAPI : public RestAPI
{
private:
    int getBlob (sys_t sys, const char *name, char **buf, size_t *bufSize, const char *accept);

public:
    static const char *sysStr [SSCount];
    int lookupAccessMode(
            std::string subSystem, rest_access_mode_t &accessMode);

    static int buildMasterName (const char *pattern, int seqId, char *buf, size_t bufSize);
    static int buildDataName   (int n, const char *pattern, int seqId, char *buf, size_t bufSize);

    EigerRestAPI (std::string const & hostname, int port = 80, size_t numSockets=5);

    int initialize (void);
    int arm        (int *sequenceId);
    int trigger    (int timeout, double exposure = 0.0);
    int disarm     (void);
    int cancel     (void);
    int abort      (void);
    int wait       (void);
    int statusUpdate (void);

    int getFileSize (const char *filename, size_t *size);
    int waitFile    (const char *filename, double timeout = DEFAULT_TIMEOUT);
    int getFile     (const char *filename, char **buf, size_t *bufSize);
    int deleteFile  (const char *filename);

    int getMonitorImage  (char **buf, size_t *bufSize, size_t timeout = 500);
};

#endif
