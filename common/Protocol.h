#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace Protocol {
    enum MessageType : uint32_t {
        AUTH_REQ = 1,
        AUTH_RES,
        UPLOAD_REQ,
        UPLOAD_RES,
        CHUNK_DATA,
        CHUNK_ACK,
        DOWNLOAD_REQ,
        DOWNLOAD_RES,
        ERROR_RES
    };

    struct Header {
        MessageType type;
        uint32_t payloadSize;
    };
}
