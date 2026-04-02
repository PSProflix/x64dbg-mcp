#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "_plugins.h"
#include "bridgegraph.h"

#include <jansson.h>

namespace
{
    constexpr const char* kPluginName = "x64dbg_mcp";
    constexpr const char* kDefaultHost = "127.0.0.1";
    constexpr unsigned short kDefaultPort = 47063;
    constexpr duint kMaxReadSize = 1024 * 1024;

    int g_pluginHandle = 0;

    std::string hexValue(duint value)
    {
        std::ostringstream oss;
        oss << "0x" << std::hex << std::uppercase << value;
        return oss.str();
    }

    void setUint(json_t* object, const char* key, duint value)
    {
        json_object_set_new(object, key, json_integer(static_cast<json_int_t>(value)));
        std::string hexKey = std::string(key) + "_hex";
        json_object_set_new(object, hexKey.c_str(), json_string(hexValue(value).c_str()));
    }

    void setUint32(json_t* object, const char* key, DWORD value)
    {
        json_object_set_new(object, key, json_integer(static_cast<json_int_t>(value)));
        std::ostringstream oss;
        oss << "0x" << std::hex << std::uppercase << value;
        std::string hexKey = std::string(key) + "_hex";
        json_object_set_new(object, hexKey.c_str(), json_string(oss.str().c_str()));
    }

    void setString(json_t* object, const char* key, const char* value)
    {
        json_object_set_new(object, key, json_string(value ? value : ""));
    }

    bool tryGetString(json_t* params, const char* key, std::string & value, std::string & error, bool required = true)
    {
        json_t* item = json_object_get(params, key);
        if(!item)
        {
            if(required)
                error = std::string("missing string param: ") + key;
            return !required;
        }
        if(!json_is_string(item))
        {
            error = std::string("param must be a string: ") + key;
            return false;
        }
        value = json_string_value(item);
        return true;
    }

    bool tryGetBool(json_t* params, const char* key, bool & value, std::string & error, bool defaultValue = false, bool required = false)
    {
        json_t* item = json_object_get(params, key);
        if(!item)
        {
            if(required)
            {
                error = std::string("missing bool param: ") + key;
                return false;
            }
            value = defaultValue;
            return true;
        }
        if(!json_is_boolean(item))
        {
            error = std::string("param must be a bool: ") + key;
            return false;
        }
        value = json_is_true(item);
        return true;
    }

    bool parseUintText(const char* text, duint & value)
    {
        if(!text || !*text)
            return false;
        char* end = nullptr;
#ifdef _WIN64
        value = _strtoui64(text, &end, 0);
#else
        value = strtoul(text, &end, 0);
#endif
        return end && *end == '\0';
    }

    bool tryGetUint(json_t* params, const char* key, duint & value, std::string & error, bool required = true, duint defaultValue = 0)
    {
        json_t* item = json_object_get(params, key);
        if(!item)
        {
            if(required)
            {
                error = std::string("missing integer param: ") + key;
                return false;
            }
            value = defaultValue;
            return true;
        }
        if(json_is_integer(item))
        {
            value = static_cast<duint>(json_integer_value(item));
            return true;
        }
        if(json_is_string(item))
        {
            if(parseUintText(json_string_value(item), value))
                return true;
        }
        error = std::string("param must be an integer or integer string: ") + key;
        return false;
    }

    std::vector<unsigned char> hexToBytes(const std::string & text, std::string & error)
    {
        std::string compact;
        compact.reserve(text.size());
        for(char ch : text)
        {
            if(ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n')
                compact.push_back(ch);
        }
        if(compact.size() % 2 != 0)
        {
            error = "hex string must contain an even number of characters";
            return {};
        }
        auto nibble = [](char ch) -> int
        {
            if(ch >= '0' && ch <= '9')
                return ch - '0';
            if(ch >= 'a' && ch <= 'f')
                return ch - 'a' + 10;
            if(ch >= 'A' && ch <= 'F')
                return ch - 'A' + 10;
            return -1;
        };
        std::vector<unsigned char> bytes;
        bytes.reserve(compact.size() / 2);
        for(size_t i = 0; i < compact.size(); i += 2)
        {
            int hi = nibble(compact[i]);
            int lo = nibble(compact[i + 1]);
            if(hi < 0 || lo < 0)
            {
                error = "hex string contains a non-hex digit";
                return {};
            }
            bytes.push_back(static_cast<unsigned char>((hi << 4) | lo));
        }
        return bytes;
    }

    std::string bytesToHex(const unsigned char* data, size_t size)
    {
        static const char* digits = "0123456789ABCDEF";
        std::string out;
        out.reserve(size * 2);
        for(size_t i = 0; i < size; ++i)
        {
            unsigned char byte = data[i];
            out.push_back(digits[byte >> 4]);
            out.push_back(digits[byte & 0x0F]);
        }
        return out;
    }

    const char* functionTypeName(FUNCTYPE type)
    {
        switch(type)
        {
        case FUNC_BEGIN: return "begin";
        case FUNC_MIDDLE: return "middle";
        case FUNC_END: return "end";
        case FUNC_SINGLE: return "single";
        default: return "none";
        }
    }

    const char* loopTypeName(LOOPTYPE type)
    {
        switch(type)
        {
        case LOOP_BEGIN: return "begin";
        case LOOP_MIDDLE: return "middle";
        case LOOP_ENTRY: return "entry";
        case LOOP_END: return "end";
        case LOOP_SINGLE: return "single";
        default: return "none";
        }
    }

    const char* argTypeName(ARGTYPE type)
    {
        switch(type)
        {
        case ARG_BEGIN: return "begin";
        case ARG_MIDDLE: return "middle";
        case ARG_END: return "end";
        case ARG_SINGLE: return "single";
        default: return "none";
        }
    }

    const char* xrefTypeName(XREFTYPE type)
    {
        switch(type)
        {
        case XREF_DATA: return "data";
        case XREF_JMP: return "jump";
        case XREF_CALL: return "call";
        default: return "none";
        }
    }

    const char* bpTypeName(BPXTYPE type)
    {
        switch(type)
        {
        case bp_normal: return "normal";
        case bp_hardware: return "hardware";
        case bp_memory: return "memory";
        case bp_dll: return "dll";
        case bp_exception: return "exception";
        default: return "none";
        }
    }

    json_t* serializeSessionInfo()
    {
        json_t* obj = json_object();
        setUint32(obj, "host_pid", GetCurrentProcessId());
        setString(obj, "plugin_name", kPluginName);
        setString(obj, "arch", sizeof(void*) == 8 ? "x64" : "x86");
        json_object_set_new(obj, "is_debugging", json_boolean(DbgIsDebugging()));
        json_object_set_new(obj, "is_running", json_boolean(DbgIsRunning()));
        json_object_set_new(obj, "is_run_locked", json_boolean(DbgIsRunLocked()));
        setUint32(obj, "debuggee_pid", DbgGetProcessId());
        setUint32(obj, "thread_id", DbgGetThreadId());
        setUint(obj, "process_handle", reinterpret_cast<duint>(DbgGetProcessHandle()));
        setUint(obj, "thread_handle", reinterpret_cast<duint>(DbgGetThreadHandle()));
        return obj;
    }

    json_t* serializeDisasmArg(const DISASM_ARG & arg)
    {
        json_t* obj = json_object();
        json_object_set_new(obj, "type", json_integer(arg.type));
        json_object_set_new(obj, "segment", json_integer(arg.segment));
        setString(obj, "mnemonic", arg.mnemonic);
        setUint(obj, "constant", arg.constant);
        setUint(obj, "value", arg.value);
        setUint(obj, "memvalue", arg.memvalue);
        return obj;
    }

    json_t* serializeDisasm(const DISASM_INSTR & instr)
    {
        json_t* obj = json_object();
        setString(obj, "instruction", instr.instruction);
        json_object_set_new(obj, "type", json_integer(instr.type));
        json_object_set_new(obj, "argcount", json_integer(instr.argcount));
        json_object_set_new(obj, "instr_size", json_integer(instr.instr_size));
        json_t* args = json_array();
        for(int i = 0; i < instr.argcount && i < 3; ++i)
            json_array_append_new(args, serializeDisasmArg(instr.arg[i]));
        json_object_set_new(obj, "args", args);
        return obj;
    }

    json_t* serializeDisasmFast(const BASIC_INSTRUCTION_INFO & info)
    {
        json_t* obj = json_object();
        json_object_set_new(obj, "type", json_integer(info.type));
        setUint(obj, "addr", info.addr);
        json_object_set_new(obj, "branch", json_boolean(info.branch));
        json_object_set_new(obj, "call", json_boolean(info.call));
        json_object_set_new(obj, "size", json_integer(info.size));
        setString(obj, "instruction", info.instruction);
        json_t* value = json_object();
        setUint(value, "value", info.value.value);
        json_object_set_new(value, "size", json_integer(info.value.size));
        json_object_set_new(obj, "value_info", value);
        json_t* memory = json_object();
        setUint(memory, "value", info.memory.value);
        json_object_set_new(memory, "size", json_integer(info.memory.size));
        setString(memory, "mnemonic", info.memory.mnemonic);
        json_object_set_new(obj, "memory_info", memory);
        return obj;
    }

    json_t* serializeBreakpoint(const BRIDGEBP & bp)
    {
        json_t* obj = json_object();
        json_object_set_new(obj, "type", json_integer(bp.type));
        setString(obj, "type_name", bpTypeName(bp.type));
        setUint(obj, "addr", bp.addr);
        json_object_set_new(obj, "enabled", json_boolean(bp.enabled));
        json_object_set_new(obj, "singleshoot", json_boolean(bp.singleshoot));
        json_object_set_new(obj, "active", json_boolean(bp.active));
        setString(obj, "name", bp.name);
        setString(obj, "module", bp.mod);
        json_object_set_new(obj, "slot", json_integer(bp.slot));
        json_object_set_new(obj, "type_ex", json_integer(bp.typeEx));
        json_object_set_new(obj, "hw_size", json_integer(bp.hwSize));
        json_object_set_new(obj, "hit_count", json_integer(bp.hitCount));
        json_object_set_new(obj, "fast_resume", json_boolean(bp.fastResume));
        json_object_set_new(obj, "silent", json_boolean(bp.silent));
        setString(obj, "break_condition", bp.breakCondition);
        setString(obj, "log_text", bp.logText);
        setString(obj, "log_condition", bp.logCondition);
        setString(obj, "command_text", bp.commandText);
        setString(obj, "command_condition", bp.commandCondition);
        return obj;
    }

    json_t* serializeThread(const THREADALLINFO & thread)
    {
        json_t* obj = json_object();
        setUint(obj, "handle", reinterpret_cast<duint>(thread.BasicInfo.Handle));
        setUint32(obj, "thread_id", thread.BasicInfo.ThreadId);
        json_object_set_new(obj, "thread_number", json_integer(thread.BasicInfo.ThreadNumber));
        setUint(obj, "start_address", thread.BasicInfo.ThreadStartAddress);
        setUint(obj, "teb", thread.BasicInfo.ThreadLocalBase);
        setString(obj, "name", thread.BasicInfo.threadName);
        setUint(obj, "cip", thread.ThreadCip);
        json_object_set_new(obj, "suspend_count", json_integer(thread.SuspendCount));
        json_object_set_new(obj, "priority", json_integer(thread.Priority));
        json_object_set_new(obj, "wait_reason", json_integer(thread.WaitReason));
        setUint32(obj, "last_error", thread.LastError);
        json_object_set_new(obj, "cycles", json_integer(static_cast<json_int_t>(thread.Cycles)));
        return obj;
    }

    json_t* serializeRegs()
    {
        REGDUMP regs = {};
        if(!DbgGetRegDump(&regs))
            return nullptr;
        json_t* obj = json_object();
        setUint(obj, "cax", regs.regcontext.cax);
        setUint(obj, "cbx", regs.regcontext.cbx);
        setUint(obj, "ccx", regs.regcontext.ccx);
        setUint(obj, "cdx", regs.regcontext.cdx);
        setUint(obj, "csp", regs.regcontext.csp);
        setUint(obj, "cbp", regs.regcontext.cbp);
        setUint(obj, "csi", regs.regcontext.csi);
        setUint(obj, "cdi", regs.regcontext.cdi);
#ifdef _WIN64
        setUint(obj, "r8", regs.regcontext.r8);
        setUint(obj, "r9", regs.regcontext.r9);
        setUint(obj, "r10", regs.regcontext.r10);
        setUint(obj, "r11", regs.regcontext.r11);
        setUint(obj, "r12", regs.regcontext.r12);
        setUint(obj, "r13", regs.regcontext.r13);
        setUint(obj, "r14", regs.regcontext.r14);
        setUint(obj, "r15", regs.regcontext.r15);
#endif
        setUint(obj, "cip", regs.regcontext.cip);
        setUint(obj, "eflags", regs.regcontext.eflags);
        setUint(obj, "dr0", regs.regcontext.dr0);
        setUint(obj, "dr1", regs.regcontext.dr1);
        setUint(obj, "dr2", regs.regcontext.dr2);
        setUint(obj, "dr3", regs.regcontext.dr3);
        setUint(obj, "dr6", regs.regcontext.dr6);
        setUint(obj, "dr7", regs.regcontext.dr7);
        json_object_set_new(obj, "gs", json_integer(regs.regcontext.gs));
        json_object_set_new(obj, "fs", json_integer(regs.regcontext.fs));
        json_object_set_new(obj, "es", json_integer(regs.regcontext.es));
        json_object_set_new(obj, "ds", json_integer(regs.regcontext.ds));
        json_object_set_new(obj, "cs", json_integer(regs.regcontext.cs));
        json_object_set_new(obj, "ss", json_integer(regs.regcontext.ss));
        setUint32(obj, "last_error", regs.lastError.code);
        setString(obj, "last_error_name", regs.lastError.name);
        return obj;
    }

    json_t* serializeFunctionRange(duint start, duint end)
    {
        json_t* obj = json_object();
        setUint(obj, "start", start);
        setUint(obj, "end", end);
        return obj;
    }

    json_t* serializeSymbolInfo(const SYMBOLINFO & info)
    {
        json_t* obj = json_object();
        setUint(obj, "addr", info.addr);
        setString(obj, "decorated", info.decoratedSymbol);
        setString(obj, "undecorated", info.undecoratedSymbol);
        json_object_set_new(obj, "is_imported", json_boolean(info.isImported));
        return obj;
    }

    struct SymbolEnumState
    {
        json_t* items = nullptr;
        size_t limit = 256;
        size_t count = 0;
    };

    void cbSymbolEnum(SYMBOLINFO* symbol, void* user)
    {
        auto* state = static_cast<SymbolEnumState*>(user);
        if(!state || !state->items || state->count >= state->limit)
            return;
        json_array_append_new(state->items, serializeSymbolInfo(*symbol));
        ++state->count;
    }

    json_t* serializeCfg(const BridgeCFGraph & graph)
    {
        json_t* obj = json_object();
        setUint(obj, "entry", graph.entryPoint);
        json_t* nodes = json_array();
        for(const auto & pair : graph.nodes)
        {
            const auto & node = pair.second;
            json_t* nodeJson = json_object();
            setUint(nodeJson, "start", node.start);
            setUint(nodeJson, "end", node.end);
            setUint(nodeJson, "brtrue", node.brtrue);
            setUint(nodeJson, "brfalse", node.brfalse);
            json_object_set_new(nodeJson, "icount", json_integer(static_cast<json_int_t>(node.icount)));
            json_object_set_new(nodeJson, "terminal", json_boolean(node.terminal));
            json_object_set_new(nodeJson, "split", json_boolean(node.split));
            json_object_set_new(nodeJson, "indirectcall", json_boolean(node.indirectcall));
            json_t* exits = json_array();
            for(duint exit : node.exits)
            {
                json_t* exitJson = json_object();
                setUint(exitJson, "addr", exit);
                json_array_append_new(exits, exitJson);
            }
            json_object_set_new(nodeJson, "exits", exits);
            json_t* instrs = json_array();
            for(const auto & instr : node.instrs)
            {
                json_t* instrJson = json_object();
                setUint(instrJson, "addr", instr.addr);
                json_object_set_new(instrJson, "bytes_hex", json_string(bytesToHex(instr.data, sizeof(instr.data)).c_str()));
                json_array_append_new(instrs, instrJson);
            }
            json_object_set_new(nodeJson, "instructions", instrs);
            json_array_append_new(nodes, nodeJson);
        }
        json_object_set_new(obj, "nodes", nodes);
        return obj;
    }

    class BridgeAgent
    {
    public:
        void start();
        void stop();
        void sendEvent(const char* eventName, json_t* payload);
        void sendSimpleEvent(const char* eventName);
        void notifyDebugStateChanged();

    private:
        void loadConfig();
        void workerLoop();
        bool connectSocket();
        void closeSocket();
        bool isSocketConnected();
        bool sendJson(json_t* root);
        void sendHello();
        void handleLine(const std::string & line);
        json_t* dispatch(const std::string & method, json_t* params, std::string & error);

        std::atomic<bool> stopFlag_ = false;
        std::thread worker_;
        std::mutex socketMutex_;
        SOCKET socket_ = INVALID_SOCKET;
        std::string host_ = kDefaultHost;
        unsigned short port_ = kDefaultPort;
        std::string sessionId_;
    };

    BridgeAgent g_bridgeAgent;

    void BridgeAgent::start()
    {
        stopFlag_ = false;
        loadConfig();
        sessionId_ = std::string(kPluginName) + "-" + std::to_string(GetCurrentProcessId()) + "-" + (sizeof(void*) == 8 ? "x64" : "x86");
        worker_ = std::thread(&BridgeAgent::workerLoop, this);
    }

    void BridgeAgent::stop()
    {
        stopFlag_ = true;
        closeSocket();
        if(worker_.joinable())
            worker_.join();
    }

    void BridgeAgent::sendEvent(const char* eventName, json_t* payload)
    {
        json_t* root = json_object();
        json_object_set_new(root, "type", json_string("event"));
        json_object_set_new(root, "event", json_string(eventName));
        json_object_set_new(root, "session_id", json_string(sessionId_.c_str()));
        json_object_set_new(root, "timestamp_ms", json_integer(static_cast<json_int_t>(GetTickCount64())));
        json_object_set_new(root, "payload", payload ? payload : json_object());
        sendJson(root);
        json_decref(root);
    }

    void BridgeAgent::sendSimpleEvent(const char* eventName)
    {
        sendEvent(eventName, json_object());
    }

    void BridgeAgent::notifyDebugStateChanged()
    {
        if(!DbgIsDebugging())
            closeSocket();
    }

    void BridgeAgent::loadConfig()
    {
        char hostBuf[128] = {};
        DWORD hostLen = GetEnvironmentVariableA("X64DBG_MCP_HOST", hostBuf, static_cast<DWORD>(sizeof(hostBuf)));
        host_ = (hostLen > 0 && hostLen < sizeof(hostBuf)) ? hostBuf : kDefaultHost;

        char portBuf[32] = {};
        DWORD portLen = GetEnvironmentVariableA("X64DBG_MCP_PORT", portBuf, static_cast<DWORD>(sizeof(portBuf)));
        duint parsedPort = 0;
        if(portLen > 0 && portLen < sizeof(portBuf) && parseUintText(portBuf, parsedPort) && parsedPort <= 65535)
            port_ = static_cast<unsigned short>(parsedPort);
        else
            port_ = kDefaultPort;
    }

    void BridgeAgent::workerLoop()
    {
        WSADATA wsaData = {};
        if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            _plugin_logputs("[x64dbg_mcp] WSAStartup failed");
            return;
        }

        bool waitingForDebuggee = false;
        while(!stopFlag_)
        {
            if(!DbgIsDebugging())
            {
                if(isSocketConnected())
                    closeSocket();
                if(!waitingForDebuggee)
                {
                    _plugin_logputs("[x64dbg_mcp] waiting for a debuggee before opening MCP session");
                    waitingForDebuggee = true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                continue;
            }

            waitingForDebuggee = false;

            if(!isSocketConnected() && !connectSocket())
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }

            if(isSocketConnected())
            {
                sendHello();
                _plugin_logprintf("[x64dbg_mcp] connected to MCP bridge at %s:%u\n", host_.c_str(), port_);
            }

            std::string buffer;
            char chunk[4096];
            while(!stopFlag_)
            {
                if(!DbgIsDebugging())
                {
                    _plugin_logputs("[x64dbg_mcp] debuggee stopped; closing MCP session");
                    closeSocket();
                    break;
                }

                SOCKET currentSocket = INVALID_SOCKET;
                {
                    std::lock_guard<std::mutex> lock(socketMutex_);
                    currentSocket = socket_;
                }
                if(currentSocket == INVALID_SOCKET)
                    break;

                fd_set readSet;
                FD_ZERO(&readSet);
                FD_SET(currentSocket, &readSet);
                timeval timeout = {};
                timeout.tv_sec = 0;
                timeout.tv_usec = 250000;
                int ready = select(0, &readSet, nullptr, nullptr, &timeout);
                if(ready == 0)
                    continue;
                if(ready < 0)
                    break;

                int received = recv(currentSocket, chunk, sizeof(chunk), 0);
                if(received <= 0)
                    break;
                buffer.append(chunk, chunk + received);
                size_t pos = 0;
                while((pos = buffer.find('\n')) != std::string::npos)
                {
                    std::string line = buffer.substr(0, pos);
                    buffer.erase(0, pos + 1);
                    if(!line.empty())
                        handleLine(line);
                }
            }

            if(!stopFlag_)
                _plugin_logputs("[x64dbg_mcp] disconnected from MCP bridge");
            closeSocket();
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }

        WSACleanup();
    }

    bool BridgeAgent::connectSocket()
    {
        addrinfo hints = {};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* info = nullptr;
        std::string portText = std::to_string(port_);
        if(getaddrinfo(host_.c_str(), portText.c_str(), &hints, &info) != 0)
            return false;

        SOCKET sock = INVALID_SOCKET;
        for(addrinfo* it = info; it; it = it->ai_next)
        {
            sock = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
            if(sock == INVALID_SOCKET)
                continue;
            if(connect(sock, it->ai_addr, static_cast<int>(it->ai_addrlen)) == 0)
                break;
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
        freeaddrinfo(info);

        if(sock == INVALID_SOCKET)
            return false;

        DWORD one = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));

        std::lock_guard<std::mutex> lock(socketMutex_);
        socket_ = sock;
        return true;
    }

    void BridgeAgent::closeSocket()
    {
        std::lock_guard<std::mutex> lock(socketMutex_);
        if(socket_ != INVALID_SOCKET)
        {
            shutdown(socket_, SD_BOTH);
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
    }

    bool BridgeAgent::isSocketConnected()
    {
        std::lock_guard<std::mutex> lock(socketMutex_);
        return socket_ != INVALID_SOCKET;
    }

    bool BridgeAgent::sendJson(json_t* root)
    {
        if(!root)
            return false;
        char* raw = json_dumps(root, JSON_COMPACT);
        if(!raw)
            return false;
        std::string line(raw);
        free(raw);
        line.push_back('\n');

        std::lock_guard<std::mutex> lock(socketMutex_);
        if(socket_ == INVALID_SOCKET)
            return false;
        const char* data = line.data();
        int remaining = static_cast<int>(line.size());
        while(remaining > 0)
        {
            int sent = send(socket_, data, remaining, 0);
            if(sent <= 0)
                return false;
            data += sent;
            remaining -= sent;
        }
        return true;
    }

    void BridgeAgent::sendHello()
    {
        json_t* root = json_object();
        json_object_set_new(root, "type", json_string("hello"));
        json_object_set_new(root, "session_id", json_string(sessionId_.c_str()));
        json_object_set_new(root, "plugin_name", json_string(kPluginName));
        json_object_set_new(root, "plugin_version", json_integer(1));
        json_object_set_new(root, "arch", json_string(sizeof(void*) == 8 ? "x64" : "x86"));
        json_object_set_new(root, "host_pid", json_integer(static_cast<json_int_t>(GetCurrentProcessId())));
        json_object_set_new(root, "connected_at_ms", json_integer(static_cast<json_int_t>(GetTickCount64())));
        json_object_set_new(root, "capabilities", json_pack("[s,s,s]", "commands", "sdk_bridge", "events"));
        json_object_set_new(root, "debugger", serializeSessionInfo());
        sendJson(root);
        json_decref(root);
    }

    void BridgeAgent::handleLine(const std::string & line)
    {
        json_error_t errorInfo = {};
        json_t* root = json_loads(line.c_str(), 0, &errorInfo);
        if(!root || !json_is_object(root))
        {
            if(root)
                json_decref(root);
            return;
        }

        const char* type = json_string_value(json_object_get(root, "type"));
        if(!type || strcmp(type, "request") != 0)
        {
            json_decref(root);
            return;
        }

        const char* id = json_string_value(json_object_get(root, "id"));
        const char* method = json_string_value(json_object_get(root, "method"));
        json_t* params = json_object_get(root, "params");
        if(!json_is_object(params))
            params = json_object();

        std::string error;
        json_t* result = dispatch(method ? method : "", params, error);

        json_t* response = json_object();
        json_object_set_new(response, "type", json_string("response"));
        json_object_set_new(response, "id", json_string(id ? id : ""));
        if(result)
        {
            json_object_set_new(response, "ok", json_true());
            json_object_set_new(response, "result", result);
        }
        else
        {
            json_object_set_new(response, "ok", json_false());
            json_object_set_new(response, "error", json_string(error.empty() ? "request failed" : error.c_str()));
        }
        sendJson(response);
        json_decref(response);
        if(params != json_object_get(root, "params"))
            json_decref(params);
        json_decref(root);
    }

    json_t* BridgeAgent::dispatch(const std::string & method, json_t* params, std::string & error)
    {
        if(method == "ping")
        {
            json_t* obj = json_object();
            json_object_set_new(obj, "pong", json_true());
            return obj;
        }
        if(method == "describe_methods")
        {
            static const char* methods[] = {
                "ping", "describe_methods", "get_session_info", "wait_until_paused",
                "exec_command", "eval", "read_memory", "write_memory", "get_memory_map", "find_base",
                "module_at", "mod_base_from_name", "is_valid_read_ptr", "disasm", "disasm_fast",
                "assemble_at", "get_regs", "get_threads", "get_breakpoints", "get_watch_list",
                "get_label", "set_label", "clear_label_range", "get_comment", "set_comment",
                "clear_comment_range", "get_bookmark", "set_bookmark", "clear_bookmark_range",
                "get_function_type", "get_function", "function_overlaps", "add_function", "del_function",
                "get_argument_type", "get_argument", "argument_overlaps", "add_argument", "del_argument",
                "get_loop_type", "get_loop", "loop_overlaps", "add_loop", "del_loop",
                "set_auto_comment", "clear_auto_comment_range", "set_auto_label", "clear_auto_label_range",
                "set_auto_bookmark", "clear_auto_bookmark_range", "set_auto_function", "clear_auto_function_range",
                "add_xref", "del_all_xrefs", "get_xrefs", "get_xref_count", "get_xref_type",
                "get_string_at", "get_symbol_at", "enum_symbols", "analyze_function"
            };
            json_t* obj = json_object();
            json_t* array = json_array();
            for(const char* name : methods)
                json_array_append_new(array, json_string(name));
            json_object_set_new(obj, "methods", array);
            return obj;
        }
        if(method == "get_session_info")
            return serializeSessionInfo();
        if(method == "wait_until_paused")
        {
            json_t* obj = json_object();
            json_object_set_new(obj, "paused", json_boolean(_plugin_waituntilpaused()));
            return obj;
        }
        if(method == "exec_command")
        {
            std::string command;
            bool direct = true;
            if(!tryGetString(params, "command", command, error) || !tryGetBool(params, "direct", direct, error, true, false))
                return nullptr;
            bool ok = direct ? DbgCmdExecDirect(command.c_str()) : DbgCmdExec(command.c_str());
            json_t* obj = json_object();
            json_object_set_new(obj, "accepted", json_boolean(ok));
            json_object_set_new(obj, "direct", json_boolean(direct));
            setString(obj, "command", command.c_str());
            return obj;
        }
        if(method == "eval")
        {
            std::string expression;
            if(!tryGetString(params, "expression", expression, error))
                return nullptr;
            bool success = false;
            duint value = DbgEval(expression.c_str(), &success);
            json_t* obj = json_object();
            json_object_set_new(obj, "success", json_boolean(success));
            setUint(obj, "value", value);
            setString(obj, "expression", expression.c_str());
            return obj;
        }
        if(method == "read_memory")
        {
            duint address = 0;
            duint size = 0;
            if(!tryGetUint(params, "address", address, error) || !tryGetUint(params, "size", size, error))
                return nullptr;
            if(size > kMaxReadSize)
            {
                error = "read size exceeds 1 MiB limit";
                return nullptr;
            }
            std::vector<unsigned char> buffer(size);
            bool ok = size == 0 || DbgMemRead(address, buffer.data(), size);
            if(!ok)
            {
                error = "DbgMemRead failed";
                return nullptr;
            }
            json_t* obj = json_object();
            setUint(obj, "address", address);
            json_object_set_new(obj, "size", json_integer(static_cast<json_int_t>(size)));
            json_object_set_new(obj, "data_hex", json_string(bytesToHex(buffer.data(), buffer.size()).c_str()));
            return obj;
        }
        if(method == "write_memory")
        {
            duint address = 0;
            std::string dataHex;
            if(!tryGetUint(params, "address", address, error) || !tryGetString(params, "data_hex", dataHex, error))
                return nullptr;
            std::vector<unsigned char> bytes = hexToBytes(dataHex, error);
            if(!error.empty())
                return nullptr;
            bool ok = bytes.empty() || DbgMemWrite(address, bytes.data(), bytes.size());
            json_t* obj = json_object();
            json_object_set_new(obj, "written", json_boolean(ok));
            json_object_set_new(obj, "size", json_integer(static_cast<json_int_t>(bytes.size())));
            setUint(obj, "address", address);
            return obj;
        }
        if(method == "get_memory_map")
        {
            MEMMAP memmap = {};
            if(!DbgMemMap(&memmap))
            {
                error = "DbgMemMap failed";
                return nullptr;
            }
            json_t* obj = json_object();
            json_t* pages = json_array();
            for(int i = 0; i < memmap.count; ++i)
            {
                const auto & page = memmap.page[i];
                json_t* pageJson = json_object();
                setUint(pageJson, "base", reinterpret_cast<duint>(page.mbi.BaseAddress));
                setUint(pageJson, "allocation_base", reinterpret_cast<duint>(page.mbi.AllocationBase));
                setUint(pageJson, "region_size", static_cast<duint>(page.mbi.RegionSize));
                json_object_set_new(pageJson, "allocation_protect", json_integer(page.mbi.AllocationProtect));
                json_object_set_new(pageJson, "protect", json_integer(page.mbi.Protect));
                json_object_set_new(pageJson, "state", json_integer(page.mbi.State));
                json_object_set_new(pageJson, "type", json_integer(page.mbi.Type));
                setString(pageJson, "info", page.info);
                json_array_append_new(pages, pageJson);
            }
            json_object_set_new(obj, "count", json_integer(memmap.count));
            json_object_set_new(obj, "pages", pages);
            if(memmap.page)
                BridgeFree(memmap.page);
            return obj;
        }
        if(method == "find_base")
        {
            duint address = 0;
            duint size = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            duint base = DbgMemFindBaseAddr(address, &size);
            json_t* obj = json_object();
            setUint(obj, "base", base);
            setUint(obj, "size", size);
            return obj;
        }
        if(method == "module_at")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            char module[MAX_MODULE_SIZE] = {};
            bool ok = DbgGetModuleAt(address, module);
            json_t* obj = json_object();
            json_object_set_new(obj, "found", json_boolean(ok));
            setString(obj, "module", module);
            return obj;
        }
        if(method == "mod_base_from_name")
        {
            std::string name;
            if(!tryGetString(params, "name", name, error))
                return nullptr;
            duint base = DbgModBaseFromName(name.c_str());
            json_t* obj = json_object();
            setUint(obj, "base", base);
            setString(obj, "name", name.c_str());
            return obj;
        }
        if(method == "is_valid_read_ptr")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "valid", json_boolean(DbgMemIsValidReadPtr(address)));
            setUint(obj, "address", address);
            return obj;
        }
        if(method == "disasm")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            DISASM_INSTR instr = {};
            DbgDisasmAt(address, &instr);
            return serializeDisasm(instr);
        }
        if(method == "disasm_fast")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            BASIC_INSTRUCTION_INFO info = {};
            DbgDisasmFastAt(address, &info);
            return serializeDisasmFast(info);
        }
        if(method == "assemble_at")
        {
            duint address = 0;
            std::string instruction;
            if(!tryGetUint(params, "address", address, error) || !tryGetString(params, "instruction", instruction, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "assembled", json_boolean(DbgAssembleAt(address, instruction.c_str())));
            setUint(obj, "address", address);
            setString(obj, "instruction", instruction.c_str());
            return obj;
        }
        if(method == "get_regs")
        {
            json_t* regs = serializeRegs();
            if(!regs)
            {
                error = "DbgGetRegDump failed";
                return nullptr;
            }
            return regs;
        }
        if(method == "get_threads")
        {
            THREADLIST threadList = {};
            DbgGetThreadList(&threadList);
            json_t* obj = json_object();
            json_object_set_new(obj, "count", json_integer(threadList.count));
            json_object_set_new(obj, "current_thread", json_integer(threadList.CurrentThread));
            json_t* items = json_array();
            for(int i = 0; i < threadList.count; ++i)
                json_array_append_new(items, serializeThread(threadList.list[i]));
            json_object_set_new(obj, "threads", items);
            if(threadList.list)
                BridgeFree(threadList.list);
            return obj;
        }
        if(method == "get_breakpoints")
        {
            json_t* obj = json_object();
            json_t* items = json_array();
            json_t* typeItem = json_object_get(params, "type");
            std::vector<BPXTYPE> types;
            if(typeItem && json_is_integer(typeItem))
                types.push_back(static_cast<BPXTYPE>(json_integer_value(typeItem)));
            else
                types = {bp_normal, bp_hardware, bp_memory, bp_dll, bp_exception};
            for(BPXTYPE type : types)
            {
                BPMAP map = {};
                DbgGetBpList(type, &map);
                for(int i = 0; i < map.count; ++i)
                    json_array_append_new(items, serializeBreakpoint(map.bp[i]));
                if(map.bp)
                    BridgeFree(map.bp);
            }
            json_object_set_new(obj, "breakpoints", items);
            json_object_set_new(obj, "count", json_integer(static_cast<json_int_t>(json_array_size(items))));
            return obj;
        }
        if(method == "get_watch_list")
        {
            BridgeList<WATCHINFO> watches;
            if(!DbgGetWatchList(&watches))
            {
                error = "DbgGetWatchList failed";
                return nullptr;
            }
            json_t* obj = json_object();
            json_t* items = json_array();
            for(int i = 0; i < watches.Count(); ++i)
            {
                json_t* watch = json_object();
                setString(watch, "name", watches[i].WatchName);
                setString(watch, "expression", watches[i].Expression);
                json_object_set_new(watch, "window", json_integer(watches[i].window));
                json_object_set_new(watch, "id", json_integer(watches[i].id));
                json_object_set_new(watch, "var_type", json_integer(watches[i].varType));
                json_object_set_new(watch, "watchdog_mode", json_integer(watches[i].watchdogMode));
                setUint(watch, "value", watches[i].value);
                json_object_set_new(watch, "watchdog_triggered", json_boolean(watches[i].watchdogTriggered));
                json_array_append_new(items, watch);
            }
            json_object_set_new(obj, "count", json_integer(watches.Count()));
            json_object_set_new(obj, "watches", items);
            return obj;
        }
        if(method == "get_label")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            char text[MAX_LABEL_SIZE] = {};
            bool found = DbgGetLabelAt(address, SEG_DEFAULT, text);
            json_t* obj = json_object();
            json_object_set_new(obj, "found", json_boolean(found));
            setString(obj, "text", text);
            return obj;
        }
        if(method == "set_label")
        {
            duint address = 0;
            std::string text;
            if(!tryGetUint(params, "address", address, error) || !tryGetString(params, "text", text, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "updated", json_boolean(DbgSetLabelAt(address, text.c_str())));
            return obj;
        }
        if(method == "clear_label_range")
        {
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "start", start, error) || !tryGetUint(params, "end", end, error))
                return nullptr;
            DbgClearLabelRange(start, end);
            return serializeFunctionRange(start, end);
        }
        if(method == "get_comment")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            char text[MAX_COMMENT_SIZE] = {};
            bool found = DbgGetCommentAt(address, text);
            json_t* obj = json_object();
            json_object_set_new(obj, "found", json_boolean(found));
            setString(obj, "text", text);
            return obj;
        }
        if(method == "set_comment")
        {
            duint address = 0;
            std::string text;
            if(!tryGetUint(params, "address", address, error) || !tryGetString(params, "text", text, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "updated", json_boolean(DbgSetCommentAt(address, text.c_str())));
            return obj;
        }
        if(method == "clear_comment_range")
        {
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "start", start, error) || !tryGetUint(params, "end", end, error))
                return nullptr;
            DbgClearCommentRange(start, end);
            return serializeFunctionRange(start, end);
        }
        if(method == "get_bookmark")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "enabled", json_boolean(DbgGetBookmarkAt(address)));
            return obj;
        }
        if(method == "set_bookmark")
        {
            duint address = 0;
            bool enabled = true;
            if(!tryGetUint(params, "address", address, error) || !tryGetBool(params, "enabled", enabled, error, true, false))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "updated", json_boolean(DbgSetBookmarkAt(address, enabled)));
            return obj;
        }
        if(method == "clear_bookmark_range")
        {
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "start", start, error) || !tryGetUint(params, "end", end, error))
                return nullptr;
            DbgClearBookmarkRange(start, end);
            return serializeFunctionRange(start, end);
        }
        if(method == "get_function_type")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            FUNCTYPE type = DbgGetFunctionTypeAt(address);
            json_t* obj = json_object();
            json_object_set_new(obj, "type", json_integer(type));
            setString(obj, "name", functionTypeName(type));
            return obj;
        }
        if(method == "get_function")
        {
            duint address = 0;
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            bool found = DbgFunctionGet(address, &start, &end);
            json_t* obj = json_object();
            json_object_set_new(obj, "found", json_boolean(found));
            if(found)
            {
                setUint(obj, "start", start);
                setUint(obj, "end", end);
            }
            return obj;
        }
        if(method == "function_overlaps")
        {
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "start", start, error) || !tryGetUint(params, "end", end, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "overlaps", json_boolean(DbgFunctionOverlaps(start, end)));
            return obj;
        }
        if(method == "add_function")
        {
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "start", start, error) || !tryGetUint(params, "end", end, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "created", json_boolean(DbgFunctionAdd(start, end)));
            return obj;
        }
        if(method == "del_function")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "deleted", json_boolean(DbgFunctionDel(address)));
            return obj;
        }
        if(method == "get_argument_type")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            ARGTYPE type = DbgGetArgTypeAt(address);
            json_t* obj = json_object();
            json_object_set_new(obj, "type", json_integer(type));
            setString(obj, "name", argTypeName(type));
            return obj;
        }
        if(method == "get_argument")
        {
            duint address = 0;
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            bool found = DbgArgumentGet(address, &start, &end);
            json_t* obj = json_object();
            json_object_set_new(obj, "found", json_boolean(found));
            if(found)
            {
                setUint(obj, "start", start);
                setUint(obj, "end", end);
            }
            return obj;
        }
        if(method == "argument_overlaps")
        {
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "start", start, error) || !tryGetUint(params, "end", end, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "overlaps", json_boolean(DbgArgumentOverlaps(start, end)));
            return obj;
        }
        if(method == "add_argument")
        {
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "start", start, error) || !tryGetUint(params, "end", end, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "created", json_boolean(DbgArgumentAdd(start, end)));
            return obj;
        }
        if(method == "del_argument")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "deleted", json_boolean(DbgArgumentDel(address)));
            return obj;
        }
        if(method == "get_loop_type")
        {
            duint address = 0;
            duint depth = 0;
            if(!tryGetUint(params, "address", address, error) || !tryGetUint(params, "depth", depth, error, false, 0))
                return nullptr;
            LOOPTYPE type = DbgGetLoopTypeAt(address, static_cast<int>(depth));
            json_t* obj = json_object();
            json_object_set_new(obj, "type", json_integer(type));
            setString(obj, "name", loopTypeName(type));
            return obj;
        }
        if(method == "get_loop")
        {
            duint address = 0;
            duint depth = 0;
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "address", address, error) || !tryGetUint(params, "depth", depth, error, false, 0))
                return nullptr;
            bool found = DbgLoopGet(static_cast<int>(depth), address, &start, &end);
            json_t* obj = json_object();
            json_object_set_new(obj, "found", json_boolean(found));
            if(found)
            {
                setUint(obj, "start", start);
                setUint(obj, "end", end);
            }
            return obj;
        }
        if(method == "loop_overlaps")
        {
            duint depth = 0;
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "depth", depth, error, false, 0) || !tryGetUint(params, "start", start, error) || !tryGetUint(params, "end", end, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "overlaps", json_boolean(DbgLoopOverlaps(static_cast<int>(depth), start, end)));
            return obj;
        }
        if(method == "add_loop")
        {
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "start", start, error) || !tryGetUint(params, "end", end, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "created", json_boolean(DbgLoopAdd(start, end)));
            return obj;
        }
        if(method == "del_loop")
        {
            duint address = 0;
            duint depth = 0;
            if(!tryGetUint(params, "address", address, error) || !tryGetUint(params, "depth", depth, error, false, 0))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "deleted", json_boolean(DbgLoopDel(static_cast<int>(depth), address)));
            return obj;
        }
        if(method == "set_auto_comment")
        {
            duint address = 0;
            std::string text;
            if(!tryGetUint(params, "address", address, error) || !tryGetString(params, "text", text, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "updated", json_boolean(DbgSetAutoCommentAt(address, text.c_str())));
            return obj;
        }
        if(method == "clear_auto_comment_range")
        {
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "start", start, error) || !tryGetUint(params, "end", end, error))
                return nullptr;
            DbgClearAutoCommentRange(start, end);
            return serializeFunctionRange(start, end);
        }
        if(method == "set_auto_label")
        {
            duint address = 0;
            std::string text;
            if(!tryGetUint(params, "address", address, error) || !tryGetString(params, "text", text, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "updated", json_boolean(DbgSetAutoLabelAt(address, text.c_str())));
            return obj;
        }
        if(method == "clear_auto_label_range")
        {
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "start", start, error) || !tryGetUint(params, "end", end, error))
                return nullptr;
            DbgClearAutoLabelRange(start, end);
            return serializeFunctionRange(start, end);
        }
        if(method == "set_auto_bookmark")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "updated", json_boolean(DbgSetAutoBookmarkAt(address)));
            return obj;
        }
        if(method == "clear_auto_bookmark_range")
        {
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "start", start, error) || !tryGetUint(params, "end", end, error))
                return nullptr;
            DbgClearAutoBookmarkRange(start, end);
            return serializeFunctionRange(start, end);
        }
        if(method == "set_auto_function")
        {
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "start", start, error) || !tryGetUint(params, "end", end, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "updated", json_boolean(DbgSetAutoFunctionAt(start, end)));
            return obj;
        }
        if(method == "clear_auto_function_range")
        {
            duint start = 0;
            duint end = 0;
            if(!tryGetUint(params, "start", start, error) || !tryGetUint(params, "end", end, error))
                return nullptr;
            DbgClearAutoFunctionRange(start, end);
            return serializeFunctionRange(start, end);
        }
        if(method == "add_xref")
        {
            duint address = 0;
            duint from = 0;
            if(!tryGetUint(params, "address", address, error) || !tryGetUint(params, "from", from, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "created", json_boolean(DbgXrefAdd(address, from)));
            return obj;
        }
        if(method == "del_all_xrefs")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "deleted", json_boolean(DbgXrefDelAll(address)));
            return obj;
        }
        if(method == "get_xrefs")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            XREF_INFO info = {};
            if(!DbgXrefGet(address, &info))
            {
                error = "DbgXrefGet failed";
                return nullptr;
            }
            json_t* obj = json_object();
            json_t* items = json_array();
            for(duint i = 0; i < info.refcount; ++i)
            {
                json_t* xref = json_object();
                setUint(xref, "addr", info.references[i].addr);
                json_object_set_new(xref, "type", json_integer(info.references[i].type));
                setString(xref, "type_name", xrefTypeName(info.references[i].type));
                json_array_append_new(items, xref);
            }
            json_object_set_new(obj, "count", json_integer(static_cast<json_int_t>(info.refcount)));
            json_object_set_new(obj, "xrefs", items);
            if(info.references)
                BridgeFree(info.references);
            return obj;
        }
        if(method == "get_xref_count")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            json_t* obj = json_object();
            json_object_set_new(obj, "count", json_integer(static_cast<json_int_t>(DbgGetXrefCountAt(address))));
            return obj;
        }
        if(method == "get_xref_type")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            XREFTYPE type = DbgGetXrefTypeAt(address);
            json_t* obj = json_object();
            json_object_set_new(obj, "type", json_integer(type));
            setString(obj, "name", xrefTypeName(type));
            return obj;
        }
        if(method == "get_string_at")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            char text[MAX_STRING_SIZE] = {};
            bool found = DbgGetStringAt(address, text);
            json_t* obj = json_object();
            json_object_set_new(obj, "found", json_boolean(found));
            setString(obj, "text", text);
            return obj;
        }
        if(method == "get_symbol_at")
        {
            duint address = 0;
            if(!tryGetUint(params, "address", address, error))
                return nullptr;
            char module[MAX_MODULE_SIZE] = {};
            if(!DbgGetModuleAt(address, module))
            {
                error = "address is not inside a known module";
                return nullptr;
            }
            duint base = DbgModBaseFromName(module);
            if(!base)
            {
                error = "failed to resolve module base";
                return nullptr;
            }
            json_t* items = json_array();
            SymbolEnumState state;
            state.items = items;
            state.limit = 100000;
            DbgSymbolEnum(base, cbSymbolEnum, &state);
            size_t count = json_array_size(items);
            for(size_t i = 0; i < count; ++i)
            {
                json_t* entry = json_array_get(items, static_cast<size_t>(i));
                json_t* addrItem = json_object_get(entry, "addr");
                if(addrItem && json_is_integer(addrItem) && static_cast<duint>(json_integer_value(addrItem)) == address)
                {
                    json_incref(entry);
                    json_decref(items);
                    return entry;
                }
            }
            json_decref(items);
            error = "symbol not found at address";
            return nullptr;
        }
        if(method == "enum_symbols")
        {
            duint base = 0;
            duint limit = 256;
            tryGetUint(params, "limit", limit, error, false, 256);
            json_t* obj = json_object();
            json_t* items = json_array();
            SymbolEnumState state;
            state.items = items;
            state.limit = static_cast<size_t>(limit);
            bool hasBase = tryGetUint(params, "base", base, error, false, 0) && base;
            if(!hasBase)
                error = "enum_symbols requires base with the bundled SDK version";
            if(error.empty())
                DbgSymbolEnum(base, cbSymbolEnum, &state);
            if(!error.empty())
            {
                json_decref(items);
                json_decref(obj);
                return nullptr;
            }
            json_object_set_new(obj, "count", json_integer(static_cast<json_int_t>(json_array_size(items))));
            json_object_set_new(obj, "symbols", items);
            return obj;
        }
        if(method == "analyze_function")
        {
            duint entry = 0;
            if(!tryGetUint(params, "entry", entry, error))
                return nullptr;
            BridgeCFGraphList graphList = {};
            if(!DbgAnalyzeFunction(entry, &graphList))
            {
                error = "DbgAnalyzeFunction failed";
                return nullptr;
            }
            BridgeCFGraph graph(&graphList, true);
            return serializeCfg(graph);
        }
        error = "unknown method: " + method;
        return nullptr;
    }

    void cbPlugin(CBTYPE cbType, void* callbackInfo)
    {
        switch(cbType)
        {
        case CB_INITDEBUG:
        {
            g_bridgeAgent.notifyDebugStateChanged();
            auto* info = static_cast<PLUG_CB_INITDEBUG*>(callbackInfo);
            json_t* payload = json_object();
            setString(payload, "file", info ? info->szFileName : "");
            g_bridgeAgent.sendEvent("initdebug", payload);
            break;
        }
        case CB_STOPDEBUG:
            g_bridgeAgent.notifyDebugStateChanged();
            g_bridgeAgent.sendSimpleEvent("stopdebug");
            break;
        case CB_CREATEPROCESS:
        {
            g_bridgeAgent.notifyDebugStateChanged();
            auto* info = static_cast<PLUG_CB_CREATEPROCESS*>(callbackInfo);
            json_t* payload = json_object();
            if(info && info->fdProcessInfo)
                setUint32(payload, "pid", info->fdProcessInfo->dwProcessId);
            setString(payload, "file", info ? info->DebugFileName : "");
            g_bridgeAgent.sendEvent("createprocess", payload);
            break;
        }
        case CB_EXITPROCESS:
        {
            auto* info = static_cast<PLUG_CB_EXITPROCESS*>(callbackInfo);
            json_t* payload = json_object();
            if(info && info->ExitProcess)
                setUint32(payload, "exit_code", info->ExitProcess->dwExitCode);
            g_bridgeAgent.sendEvent("exitprocess", payload);
            g_bridgeAgent.notifyDebugStateChanged();
            break;
        }
        case CB_CREATETHREAD:
        {
            auto* info = static_cast<PLUG_CB_CREATETHREAD*>(callbackInfo);
            json_t* payload = json_object();
            if(info)
                setUint32(payload, "thread_id", info->dwThreadId);
            g_bridgeAgent.sendEvent("createthread", payload);
            break;
        }
        case CB_EXITTHREAD:
        {
            auto* info = static_cast<PLUG_CB_EXITTHREAD*>(callbackInfo);
            json_t* payload = json_object();
            if(info)
                setUint32(payload, "thread_id", info->dwThreadId);
            g_bridgeAgent.sendEvent("exitthread", payload);
            break;
        }
        case CB_SYSTEMBREAKPOINT:
            g_bridgeAgent.sendSimpleEvent("systembreakpoint");
            break;
        case CB_LOADDLL:
        {
            auto* info = static_cast<PLUG_CB_LOADDLL*>(callbackInfo);
            json_t* payload = json_object();
            setString(payload, "module", info ? info->modname : "");
            if(info && info->modInfo)
                setUint(payload, "base", static_cast<duint>(info->modInfo->BaseOfImage));
            g_bridgeAgent.sendEvent("loaddll", payload);
            break;
        }
        case CB_UNLOADDLL:
            g_bridgeAgent.sendSimpleEvent("unloaddll");
            break;
        case CB_OUTPUTDEBUGSTRING:
            g_bridgeAgent.sendSimpleEvent("outputdebugstring");
            break;
        case CB_EXCEPTION:
        {
            auto* info = static_cast<PLUG_CB_EXCEPTION*>(callbackInfo);
            json_t* payload = json_object();
            if(info && info->Exception)
            {
                setUint32(payload, "code", info->Exception->ExceptionRecord.ExceptionCode);
                json_object_set_new(payload, "first_chance", json_boolean(info->Exception->dwFirstChance != 0));
                setUint(payload, "address", reinterpret_cast<duint>(info->Exception->ExceptionRecord.ExceptionAddress));
            }
            g_bridgeAgent.sendEvent("exception", payload);
            break;
        }
        case CB_BREAKPOINT:
        {
            auto* info = static_cast<PLUG_CB_BREAKPOINT*>(callbackInfo);
            json_t* payload = info && info->breakpoint ? serializeBreakpoint(*info->breakpoint) : json_object();
            g_bridgeAgent.sendEvent("breakpoint", payload);
            break;
        }
        case CB_PAUSEDEBUG:
            g_bridgeAgent.sendSimpleEvent("paused");
            break;
        case CB_RESUMEDEBUG:
            g_bridgeAgent.sendSimpleEvent("resumed");
            break;
        case CB_STEPPED:
            g_bridgeAgent.sendSimpleEvent("stepped");
            break;
        case CB_ATTACH:
        {
            g_bridgeAgent.notifyDebugStateChanged();
            auto* info = static_cast<PLUG_CB_ATTACH*>(callbackInfo);
            json_t* payload = json_object();
            if(info)
                setUint32(payload, "pid", info->dwProcessId);
            g_bridgeAgent.sendEvent("attach", payload);
            break;
        }
        case CB_DETACH:
            g_bridgeAgent.notifyDebugStateChanged();
            g_bridgeAgent.sendSimpleEvent("detach");
            break;
        default:
            break;
        }
    }
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = 1;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, sizeof(initStruct->pluginName), kPluginName, _TRUNCATE);
    g_pluginHandle = initStruct->pluginHandle;

    const CBTYPE callbacks[] = {
        CB_INITDEBUG, CB_STOPDEBUG, CB_CREATEPROCESS, CB_EXITPROCESS,
        CB_CREATETHREAD, CB_EXITTHREAD, CB_SYSTEMBREAKPOINT, CB_LOADDLL, CB_UNLOADDLL,
        CB_OUTPUTDEBUGSTRING, CB_EXCEPTION, CB_BREAKPOINT, CB_PAUSEDEBUG, CB_RESUMEDEBUG,
        CB_STEPPED, CB_ATTACH, CB_DETACH
    };
    for(CBTYPE cb : callbacks)
        _plugin_registercallback(g_pluginHandle, cb, cbPlugin);

    g_bridgeAgent.start();
    _plugin_logputs("[x64dbg_mcp] plugin initialized");
    return true;
}

extern "C" __declspec(dllexport) void plugstop()
{
    g_bridgeAgent.stop();
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*)
{
}
