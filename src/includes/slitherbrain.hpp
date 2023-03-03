#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <err.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <ctime>
#include <random>
#include <filesystem>
#include <memory>
#include <array>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <regex>
#include <seccomp.h>
#include <thread>
#include <signal.h>

#define NEWLINE "\n"
#define QUOTE '"'
#define ESCAPE '\\'
#define FSLASH '/'
#define NULLCHAR '\0'
#define ALNUM 25
#define TMPSZ 10
#define RE_IPV4 "^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.|:|$)){4}\\d{2,5})"
#define RE_IPV6 "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
#define BUFFSIZE 4096
#define ENDPOINT_EXEC "/execute"
#define METHOD "POST"
#define VC "HTTP/1.1"
#define CRLF "\r\n"
#define CRLFX2 "\r\n\r\n"
#define STATUS_OK "200 Ok"
#define STATUS_NF "404 Not Found"
#define STATUS_MNA "405 Method Not Allowed"
#define STATUS_SE "500 Internal Sever Error"
#define STATUS_UE "422 Unprocessable Entity"
#define STATUS_BR "400 Bad Request"
#define TIME_FORMAT "%a, %d %b %Y %I:%M:%S GMT"
#define SERVER_NAME "Slitherbrain Python Code Runner Revision 1"
#define CONT_TYPE "text/plain"
#define CHECKSUM_HN "Checksum: "
#define SERVER_NAME_HN "Server: "
#define DATE_HN "Date: "
#define CONT_LEN_HN "Content-Length: "
#define CONT_TYPE_HN "Content-Type: "
#define BODY_ERR "Error Ocurred"

#define ERR_EXIT(message)                              \
                                                       \
    do                                                 \
    {                                                  \
        cout << "\033[1;31mError: \033[0m" << message; \
        exit(1);                                       \
    } while (0)

#define POX_PRIMNUM 32
#define POX_BLOCKNUM 64
#define POX_PORTNUM 16
#define POX_FACTNUM 4
#define POX_ROUNDNUM 8

#define ROT16LEFT4(num) ((num << 4) | (num >> (16 - 4)))
#define ROT16RIGHT4(num) ((num >> 4) | (num << (16 - 4)))

#define POX_ALPHA(a) a |= ROT16LEFT4(a) | ROT16RIGHT4(a * 2)
#define POX_DELTA(a, b) b = (ROT16LEFT4(b) ^ a)| 0xffcd
#define POX_THETA(a, b, c) c = (a >> (ROT16RIGHT4(b & a))) >> 2
#define POX_OMEGA(a, b, c, d) d = ((a >> 2) ^ (b >> 4) ^ (c >> 6)) | ROT16LEFT4(d)

void sighandle(int signum);

namespace slitherbrain
{
    using namespace std;

    namespace args
    {
        void parseArgsAndRun(int argc, char **argv, volatile sig_atomic_t &sigc);
        string hasFlagIfSoRemoveMarker(char *arg, const char *flag);
    }
    namespace process
    {
        string runSlitherRunProcess(string slitherrun_path, string python_path, string disallowed_calls, string code);
        string execCommand(string cmd);
        void sandboxProcess(vector<string> to_disallow);
    }
    namespace net
    {
        typedef enum NetworkAddressType
        {
            AddrTypeIPV4,
            AddrTypeIPV6,
        } netAddr_t;

        typedef struct sockaddr_in sockAddrIn_t;
        typedef struct sockaddr *pSockAddr_t;

        sockAddrIn_t newSocketAddress(string ip, uint16_t port, netAddr_t addr_type);
        netAddr_t getAddrType(string addr);
        int listenToSocket(sockAddrIn_t &socket_addr, netAddr_t addr_type);
        int accepetNewConnection(sockAddrIn_t &socket_addr, int listener);
        string readClientConnection(int clientsock);
        void readSocketExecuteAndSendBack(int clientsock, string slitherrun_path, string python_path, string disallowed_calls);
        void serveHttpForever(string ip, int port, string slitherrun_path, string python_path, string disallowed_calls, volatile sig_atomic_t &sigc);
    }
    namespace http
    {
        typedef enum HttpParseError
        {
            ParseEmptyRequest,
            ParseWrongProtocol,
            ParseWrongMethod,
            ParseWrongEndpont,
            ParseWrongVC,
            ParseNoBody,
            ParseReqLineOk,
            ParseBadCode,
        } parseActonStat_t;

        string composeResponseLine(parseActonStat_t action_stat);
        string composeResponseHeaders(size_t clen);
        string composeResponse(parseActonStat_t action_state, string response_body);
        parseActonStat_t validateReqestLine(string requestLine);
        parseActonStat_t parseRequest(string request, string &code);
        string getCheckSum(vector<string> headers);
        bool checkCodeIntegrity(string code, string checksum);

    }
    namespace utils
    {
        typedef struct tm *pTime_t;

        string getCurrentUtcFormattedTime();
        size_t randomNum(size_t min, size_t max);
        string randomString(size_t size);
        string readConfigFile(string fpath);

    }
    namespace strtools
    {
        bool charAtRightIs(string s, char c);
        void trimCharRight(string &str, char c);
        void trimCharLeft(string &str, char c);
        void trimChar(string &str, vector<char> chars);
        vector<string> splitStr(string str, const string delimiter);
        string joinStrVector(vector<string> strs, const string delemiter);
        void replaceChar(string &str, const char c, char r);
        void escapeSequence(string &str);
    }
    namespace filetools
    {
        string pathJoinTmp(string path);
        void writeStringToFile(string fpath, string contents);
        string processCodeAndSaveTemp(string code);
        void removeScriptFile(string fpath);

    }
    namespace pox
    {
        void poxRound(uint16_t &a, uint16_t &b, uint16_t &c, uint16_t &d);
        void poxProcessBlock(const char block[POX_BLOCKNUM], uint16_t &a, uint16_t &b, uint16_t &c, uint16_t &d);
        string poxHash(string txt);
        void padString(string &txt);
        string integerToHex(uint16_t a, uint16_t b, uint16_t c, uint16_t d);
    }
    namespace consts
    {
        const regex c_IPV4_REGEX(RE_IPV4);
        const regex c_IPV6_REGEX(RE_IPV6);

        const vector<char> cTO_TRIM = {'\0', ' ', '\r', '\n', ';', '\t'};
        const vector<char> cUPPERCASE = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'M', 'N', 'O', 'P', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
        
        const uint16_t cPOX_PRIMES[POX_PRIMNUM] = {
            0xe537, 0xbd71, 0x9ef9, 0xbbcf, 0xf8dd, 0xceb7, 0xbaa1, 0x8f9f,
            0xb0ed, 0xfc4f, 0x9787, 0xf01f, 0xe1d1, 0xbcb9, 0xd565, 0xc011,
            0xc1e1, 0xb58d, 0xd4e1, 0x9ea1, 0xee49, 0x97cd, 0xdac9, 0xe257,
            0xa32b, 0xafbb, 0xa5e3, 0xfc43, 0xbf71, 0xe401, 0x8ebd, 0xd549};

        const uint16_t cPOXPRIME_INIT_A = 0x9f91;
        const uint16_t cPOXPRIME_INIT_B = 0xdb3b;
        const uint16_t cPOXPRIME_INIT_C = 0xc091;
        const uint16_t cPOXPRIME_INIT_D = 0xac8b;   
    }
}
