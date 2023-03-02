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

using namespace std;

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
typedef struct addrinfo *pAddrInfo_t;
typedef struct sockaddr_in sockAddrIn_t;
typedef struct sockaddr *pSockAddr_t;
typedef struct tm *pTime_t;

volatile sig_atomic_t sigc;

const regex c_IPV4_REGEX(RE_IPV4);
const regex c_IPV6_REGEX(RE_IPV6);

const vector<char> cTO_TRIM = {'\0', ' ', '\r', '\n', ';', '\t'};
const vector<char> cUPPERCASE = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'M', 'N', 'O', 'P', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};

typedef enum NetworkAddressType
{
    AddrTypeIPV4,
    AddrTypeIPV6,
} netAddr_t;

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

void sighandle(int signum)
{
    sigc = 1;
}

string composeResponseLine(parseActonStat_t action_stat)
{
    auto makeResp_f = [](const char *stat, string &resp_line)
    {
        stringstream strm;
        strm << VC;
        strm << ' ';
        strm << stat;
        strm << CRLF;

        resp_line = strm.str();
    };

    string resp_line;
    switch (action_stat)
    {
    case ParseEmptyRequest:
        makeResp_f(STATUS_BR, resp_line);
        break;
    case ParseWrongProtocol:
        makeResp_f(STATUS_UE, resp_line);
        break;
    case ParseWrongMethod:
        makeResp_f(STATUS_MNA, resp_line);
        break;
    case ParseWrongEndpont:
        makeResp_f(STATUS_NF, resp_line);
        break;
    case ParseWrongVC:
        makeResp_f(STATUS_UE, resp_line);
        break;
    case ParseBadCode:
        makeResp_f(STATUS_BR, resp_line);
        break;
    case ParseNoBody:
        makeResp_f(STATUS_BR, resp_line);
        break;
    case ParseReqLineOk:
        makeResp_f(STATUS_OK, resp_line);
        break;
    }

    return resp_line;
}

string composeResponseHeaders(size_t clen)
{
    stringstream strm;

    strm << DATE_HN;
    strm << getCurrentUtcFormattedTime();
    strm << CRLF;

    strm << SERVER_NAME_HN;
    strm << SERVER_NAME;
    strm << CRLF;

    if (clen > 0)
    {
        strm << CONT_TYPE_HN;
        strm << CONT_TYPE;
        strm << CRLF;

        strm << CONT_LEN_HN;
        strm << clen;
        strm << CRLFX2;
    }

    return strm.str();
}

string composeResponse(parseActonStat_t action_state, string response_body)
{
    string response_line = composeResponseLine(action_state);
    string response_headers = composeResponseHeaders(response_body.length());

    stringstream strm;

    strm << response_line;
    strm << response_headers;
    strm << response_body;

    return strm.str();
}

string getCurrentUtcFormattedTime()
{
    time_t rawtime;
    pTime_t localnow;
    pTime_t utcnow;
    char buffer[1024];

    time(&rawtime);
    localnow = localtime(&rawtime);
    utcnow = gmtime(&rawtime);

    strftime(buffer, sizeof(buffer), TIME_FORMAT, utcnow);

    return string(buffer);
}

static void sandboxProcess(vector<string> to_disallow)
{
    scmp_filter_ctx seccomp_ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!seccomp_ctx)
        err(1, "seccomp_init failed");

    string curr_call;
    for (int i = 0; i < to_disallow.size(); i++)
    {
        curr_call = to_disallow[i];

        if (seccomp_rule_add_exact(seccomp_ctx, SCMP_ACT_KILL_THREAD, seccomp_syscall_resolve_name(curr_call.c_str()), 0))
        {
            perror("seccomp_rule_add_exact failed");
            exit(1);
        }
    }

    if (seccomp_load(seccomp_ctx))
    {
        perror("seccomp_load failed");
        exit(1);
    }

    seccomp_release(seccomp_ctx);
}

size_t randomNum(size_t min, size_t max)
{
    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist6(min, max);

    return dist6(rng);
}

string randomString(size_t size)
{
    string ret;
    for (int i = 0; i < size; i++)
    {
        size_t new_rand = randomNum(0, ALNUM);
        char new_char = cUPPERCASE[new_rand];
        ret.insert(0, 1, new_char);
    }

    return ret;
}

string readConfigFile(string fpath)
{
    string curr_line;
    vector<string> config_read;
    ifstream f_configfile(fpath);
    stringstream strm;

    if (f_configfile.is_open())
    {
        while (getline(f_configfile, curr_line))
        {
            strm << curr_line;
            strm << " ";
        }
    }

    return strm.str();
}

bool charAtRightIs(string s, char c)
{
    return s[s.rfind(c)] == c;
}

void trimCharRight(string &str, char c)
{
    size_t position = 0;
    while (charAtRightIs(str, c))
    {
        str.erase(position, 1);
    }
}

void trimCharLeft(string &str, char c)
{
    size_t position = 0;
    string reverse_copy = str;
    reverse(reverse_copy.begin(), reverse_copy.end());

    while (charAtRightIs(reverse_copy, c))
    {
        reverse_copy.erase(position, 1);
        str.erase(str.length() - position - 1, 1);
    }
}

void trimChar(string &str, vector<char> chars)
{
    char curr_char;
    for (size_t i = 0; i < chars.size(); i++)
    {
        curr_char = chars[i];
        trimCharLeft(str, curr_char);
        trimCharRight(str, curr_char);
    }
}

vector<string> splitStr(string str, const string delimiter)
{
    size_t pos = 0;
    string token;
    vector<string> ret;

    while ((pos = str.find(delimiter)) != string::npos)
    {
        token = str.substr(0, pos);
        ret.push_back(token);
        str.erase(0, pos + delimiter.length());
    }

    return ret;
}

string joinStrVector(vector<string> strs, const string delemiter)
{
    stringstream strm;
    for (int i = 0; i < strs.size(); i++)
    {
        strm << strs[i];
        strm << delemiter;
    }

    return strm.str();
}

void replaceChar(string &str, const char c, char r)
{
    for (int i = 0; i < str.length(); i++)
    {
        if (str[i] == c)
            str[i] = r;
    }
}

void escapeSequence(string &str)
{
    char curr_char;
    for (size_t i = 0; i < str.length(); i++)
    {
        curr_char = str[i];
        if (curr_char == QUOTE)
        {
            if (i > 0)
            {
                if (str[i - 1] == ESCAPE)
                    continue;
                str.insert(i - 1, 1, ESCAPE);
            }
            else
            {
                str.insert(0, 1, ESCAPE);
            }
        }
    }
}

string pathJoinTmp(string path)
{
    string tmppath = filesystem::temp_directory_path();
    if (tmppath[tmppath.length() - 1] == FSLASH)
    {
        return tmppath + path;
    }

    return tmppath + FSLASH + path;
}

void writeStringToFile(string fpath, string contents)
{
    fstream ofile;
    ofile.open(fpath);
    if (!ofile)
    {
        cout << "\033Error: \033: Failed to write to file, skipped..." << endl;
    }

    ofile << contents;
    ofile.close();
}

string processCodeAndSaveTemp(string code)
{
    trimChar(code, cTO_TRIM);
    string tmppath = randomString(10);
    string joined_path = pathJoinTmp(tmppath);
    int new_file = mkstemp64((char *)joined_path.c_str());
    writeStringToFile(joined_path, code);

    return joined_path;
}

string execCommand(string cmd)
{
    char buff[BUFFSIZE];
    memset(buff, 0, BUFFSIZE);

    string out;

    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe)
    {
        ERR_EXIT("Problem opening pipe for Python");
    }

    while (fgets(buff, sizeof(buff), pipe) != NULL)
    {
        out += buff;
    }

    pclose(pipe);
    return out;
}

netAddr_t getAddrType(string addr)
{
    smatch re_match_ipv4, re_match_ipv6;
    regex_match(addr, re_match_ipv4, c_IPV4_REGEX);
    regex_match(addr, re_match_ipv6, c_IPV6_REGEX);

    if (re_match_ipv4.size() > 0)
    {
        return AddrTypeIPV4;
    }
    else if (re_match_ipv6.size() > 0)
    {
        return AddrTypeIPV6;
    }
    else
    {
        ERR_EXIT("Wrong address given, must be IPV4 or IPV6");
    }
}

string removeScriptFile(string fpath)
{
    remove(fpath.c_str());
}

// to be the main function of the slitherexec
int _main(int argc, char **argv)
{
    vector<string> unallowed_syscalls;

    for (int i = 3; i < argc; i++)
    {
        unallowed_syscalls.push_back(string(argv[i]));
    }

    sandboxProcess(unallowed_syscalls);
    string command = string(argv[1]) + " " + string(argv[2]);
    string exec_result = execCommand(command);

    cout << exec_result << endl;
}

sockAddrIn_t newSocketAddress(string ip, uint16_t port, netAddr_t addr_type)
{
    int domain;
    if (addr_type == AddrTypeIPV4)
    {
        domain = AF_INET;
    }
    else
    {
        domain = AF_INET6;
    }

    sockAddrIn_t new_sock_addr;
    new_sock_addr.sin_family = domain;
    new_sock_addr.sin_port = port;

    inet_pton(domain, ip.c_str(), &new_sock_addr.sin_addr);

    return new_sock_addr;
}

int listenToSocket(sockAddrIn_t &socket_addr, netAddr_t addr_type)
{
    int domain;
    if (addr_type == AddrTypeIPV4)
    {
        domain = AF_INET;
    }
    else
    {
        domain = AF_INET6;
    }

    int listener = socket(domain, SOCK_STREAM, 0);
    if (listener == -1)
    {
        ERR_EXIT("Problem occured with creating socket.");
    }

    if (bind(listener, (pSockAddr_t)&socket_addr, sizeof(socket_addr)) == -1)
    {
        ERR_EXIT("Problem occured with binding the socket");
    }

    if (listen(listener, SOMAXCONN) == -1)
    {
        ERR_EXIT("Problem occured with listening to the port");
    }

    return listener;
}

int accepetNewConnection(sockAddrIn_t &socket_addr, int listener)
{
    socklen_t client_size = sizeof(socket_addr);
    int clientsock = accept(listener, (pSockAddr_t)&socket_addr, &client_size);

    return clientsock;
}

string readClientConnection(int clientsock)
{
    char buff[BUFFSIZE];
    memset(buff, 0, BUFFSIZE);
    string readfully;

    int received = recv(clientsock, buff, BUFFSIZE, 0);
    while (received != 0 && received != -1)
    {
        readfully += string(buff);
        received = recv(clientsock, buff, BUFFSIZE, 0);
    }

    if (received == -1)
    {
        return NULL;
    }

    return readfully;
}

void readSocketExecuteAndSendBack(int clientsock, string slitherrun_path, string python_path, string disallowed_calls)
{
    string request = readClientConnection(clientsock);
    string code;
    auto action_stat = parseRequest(request, code);

    string resp_body;
    if (action_stat == ParseReqLineOk)
    {
        resp_body = runSlitherRunProcess(slitherrun_path, python_path, disallowed_calls, code);
    }
    else
    {
        resp_body = BODY_ERR;
    }

    auto response = composeResponse(action_stat, resp_body);
    send(clientsock, response.c_str(), response.length() + 1, 0);

    close(clientsock);
}

void serveHttpForever(string ip, int port, string slitherrun_path, string python_path, string disallowed_calls)
{
    auto addr_type = getAddrType(ip);
    auto listener_addr = newSocketAddress(ip, port, addr_type);
    auto listener = listenToSocket(listener_addr, addr_type);

    while (!sigc)
    {
        sockAddrIn_t client_addr;
        int clientsocket = accepetNewConnection(client_addr, listener);
        if (!clientsocket)
            continue;
        thread([clientsocket, slitherrun_path, python_path, disallowed_calls]()
               { readSocketExecuteAndSendBack(clientsocket, slitherrun_path, python_path, disallowed_calls); });
    }

    close(listener);
}

parseActonStat_t validateReqestLine(string requestLine)
{
    vector<string> split = splitStr(requestLine, " ");

    if (split.size() != 3)
        return ParseWrongProtocol;
    else if (split[0] != METHOD)
        return ParseWrongMethod;
    else if (!split[1].find(ENDPOINT_EXEC))
        return ParseWrongEndpont;
    else if (split[2] != VC)
        return ParseWrongVC;

    return ParseReqLineOk;
}

parseActonStat_t parseRequest(string request, string &code)
{
    vector<string> request_split = splitStr(request, CRLFX2);
    if (request_split.size() != 2)
    {
        return ParseNoBody;
    }

    code = request_split[1];
    vector<string> headers = splitStr(request_split[0], CRLF);

    string checksum = getCheckSum(headers);
    if (!checkCodeIntegrity(code, checksum))
    {
        return ParseBadCode;
    }

    string req_line = headers[0];

    return validateReqestLine(req_line);
}

string getCheckSum(vector<string> headers)
{
    string curr_line;
    for (int i = 0; i < headers.size(); i++)
    {
        curr_line = headers[i];
        trimChar(curr_line, cTO_TRIM);

        if (curr_line.rfind(CHECKSUM_HN))
        {
            curr_line.erase(0, string(CHECKSUM_HN).length());
            replaceChar(curr_line, QUOTE, NULLCHAR);
        }
    }

    return curr_line;
}

bool checkCodeIntegrity(string code, string checksum)
{
    string hash = poxHash(code);

    return hash == checksum;
}

#define POX_PRIMNUM 32
#define POX_BLOCKNUM 64
#define POX_PORTNUM 16
#define POX_FACTNUM 4

const uint16_t cPOX_PRIMES[POX_PRIMNUM] = {
    0xe537, 0xbd71, 0x9ef9, 0xbbcf, 0xf8dd, 0xceb7, 0xbaa1, 0x8f9f,
    0xb0ed, 0xfc4f, 0x9787, 0xf01f, 0xe1d1, 0xbcb9, 0xd565, 0xc011,
    0xc1e1, 0xb58d, 0xd4e1, 0x9ea1, 0xee49, 0x97cd, 0xdac9, 0xe257,
    0xa32b, 0xafbb, 0xa5e3, 0xfc43, 0xbf71, 0xe401, 0x8ebd, 0xd549};

const uint16_t cPOXPRIME1 = 0x9f91;
const uint16_t cPOXPRIME2 = 0xdb3b;
const uint16_t cPOXPRIME3 = 0xc091;
const uint16_t cPOXPRIME4 = 0xac8b;

#define ROT16LEFT4(num) ((num << 4) | (num >> (16 - 4)))
#define ROT16RIGHT4(num) ((num >> 4) | (num << (16 - 4)))

#define POX_ALPHA(a) a |= ROT16LEFT4(a) | ROT16RIGHT4(a * 2)
#define POX_DELTA(a, b) a = ROT16LEFT4(b) | 0xffcd
#define POX_THETA(a, b, c) c = (a * (ROT16RIGHT4(b + a))) >> 2
#define POX_OMEGA(a, b, c, d) a = ((a >> 2) * (b >> 4) * (c >> 6)) | ROT16LEFT4(d)

void poxRound(uint16_t &a, uint16_t &b, uint16_t &c, uint16_t &d)
{
    uint16_t tmp_a, tmp_b, tmp_c, tmp_d;
    tmp_a = a;
    tmp_b = b;
    tmp_c = c;
    tmp_d = d;

    POX_ALPHA(tmp_a);
    POX_DELTA(tmp_a, tmp_b);
    POX_THETA(tmp_a, tmp_b, tmp_c);
    POX_OMEGA(tmp_a, tmp_b, tmp_c, tmp_d);

    for (int i = POX_PRIMNUM; i > 0; i++)
    {
        tmp_a = tmp_b ^ cPOX_PRIMES[i];
        tmp_b = tmp_c & cPOX_PRIMES[i];
        tmp_c = tmp_d | cPOX_PRIMES[i];
        tmp_d = tmp_a >> 2;
    }

    a = tmp_a / 2;
    b = tmp_b / 4;
    c = tmp_c / 6;
    d = tmp_d / 8;
}

void poxProcessBlock(const char block[POX_BLOCKNUM], uint16_t &a, uint16_t &b, uint16_t &c, uint16_t &d)
{
    for (int i = 0; i < POX_BLOCKNUM; i += POX_PORTNUM)
    {
        for (int j = i; j < POX_PORTNUM; j += POX_FACTNUM)
        {
            a |= block[i];
            b ^= block[i + 1];
            c &= block[i + 2] + 1;
            d = ~block[i + 3];

            poxRound(a, b, c, d);
        }
    }
}

string poxHash(string txt)
{
    uint16_t a = cPOXPRIME1;
    uint16_t b = cPOXPRIME2;
    uint16_t c = cPOXPRIME3;
    uint16_t d = cPOXPRIME4;

    padString(txt);

    for (int i = 0; i < txt.length(); i += POX_BLOCKNUM)
    {
        string sub = txt.substr(i, POX_BLOCKNUM);
        poxProcessBlock(sub.c_str(), a, b, c, d);
    }

    integerToHex(a, b, c, d);
}

void padString(string &txt)
{
    while (txt.length() % POX_BLOCKNUM != 0)
    {
        txt.push_back(NULLCHAR);
    }
}

string integerToHex(uint16_t a, uint16_t b, uint16_t c, uint16_t d)
{
    stringstream strm;
    strm << hex << a;
    strm << hex << b;
    strm << hex << c;
    strm << hex << d;

    return strm.str();
}

string runSlitherRunProcess(string slitherrun_path, string python_path, string disallowed_calls, string code)
{
    string tmp_filep = processCodeAndSaveTemp(code);
    vector<string> command_vec = {slitherrun_path, python_path, tmp_filep, disallowed_calls};
    string command = joinStrVector(command_vec, " ");

    string result = execCommand(command);
    return result;
}

string hasFlagIfSoRemoveMarker(char *arg, const char *flag)
{
    string arg_str = string(arg);
    if (arg_str.rfind(flag))
    {
        arg_str.erase(0, string(flag).length());
        return arg_str;
    }

    return "";
}

vector<string> parseArgsAndRun(int argc, char **argv)
{
    string python_path, slitherrun_path, config_path, ip, port_str, disallowed_calls;
    uint16_t port_int;

    for (int i = 0; i < argc; i++)
    {
        python_path = hasFlagIfSoRemoveMarker(argv[i], "--pypath=");
        slitherrun_path = hasFlagIfSoRemoveMarker(argv[i], "--runnerpath=");
        config_path = hasFlagIfSoRemoveMarker(argv[i], "--confpath=");
        ip = hasFlagIfSoRemoveMarker(argv[i], "--ip=");
        port_str = hasFlagIfSoRemoveMarker(argv[i], "--port=");
    }

    if (python_path == "")
        ERR_EXIT("Must pass --pypath=<python path>");
    else if (slitherrun_path == "")
        ERR_EXIT("Must pass --runnerpath=<SlitherRun path>");
    else if (config_path == "")
        ERR_EXIT("Must pass --confpath=<Config path>");
    else if (ip == "")
        ERR_EXIT("Must pass --ip=<Host IP>");
    else if (port_str == "")
        ERR_EXIT("Must pass --port<Host port>");

    port_int = stoi(port_str);
    disallowed_calls = readConfigFile(config_path);

    serveHttpForever(ip, port_int, slitherrun_path, python_path, disallowed_calls);
}

int main(int argc, char **argv)
{
    signal(SIGINT, sighandle);
    parseArgsAndRun(argc, argv);
}