#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <err.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm> 
#include <chrono>
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

using namespace std;

#define NEWLINE "\n"
#define QUOTE '"'
#define ESCAPE '\\'
#define FSLASH '/'
#define ALNUM 25
#define TMPSZ 10
#define RE_IPV4 "^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.|:|$)){4}\\d{2,5})"
#define RE_IPV6 "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"

#define ERR_EXIT(message)                              \
                                                       \
    do                                                 \
    {                                                  \
        cout << "\033[1;31mError: \033[0m" << message; \
        exit(1);                                       \
    } while (0)
typedef struct addrinfo *pAddrInfo_t;

const regex c_IPV4_REGEX(RE_IPV4);
const regex c_IPV6_REGEX(RE_IPV6);

const vector<char> cTO_TRIM = { '\0', ' ', '\r', '\n', ';', '\t' };
const vector<char> cUPPERCASE = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'M', 'N', 'O', 'P', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};

typedef enum NetworkAddressType {
    AddrTypeIPV4,
    AddrTypeIPV6,
} netAddr_t;


static void tefnutSandBoxSeccomp(vector<string> to_disallow)
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


vector<string> readConfigFile(string &fpath) {
    string curr_line;
    vector<string> config_read;
    ifstream f_configfile(fpath);


    if (f_configfile.is_open()) {
        while (getline(f_configfile, curr_line)) {
            config_read.push_back(curr_line);
        }
    }

    return config_read;
} 

size_t randomNum(size_t min, size_t max) {
    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist6(min, max); 

    return dist6(rng);
}

string randomString(size_t size) {
    string ret;
    for (int i = 0; i < size; i++) {
        size_t new_rand = randomNum(0, ALNUM);
        char new_char = cUPPERCASE[new_rand];
        ret.insert(0, 1, new_char);
    }

    return ret;
}


vector<string> readConfigFile(string &fpath) {
    string curr_line;
    vector<string> config_read;
    ifstream f_configfile(fpath);


    if (f_configfile.is_open()) {
        while (getline(f_configfile, curr_line)) {
            config_read.push_back(curr_line);
        }
    }

    return config_read;
} 

bool charAtRightIs(string s, char c) {
    return s[s.rfind(c)] == c;
}

void trimCharRight(string &str, char c) {
    size_t position = 0;
    while (charAtRightIs(str, c)) {
        str.erase(position, 1);
    }
}

void trimCharLeft(string &str, char c) {
    size_t position = 0;
    string reverse_copy = str;
    reverse(reverse_copy.begin(), reverse_copy.end());

    while (charAtRightIs(reverse_copy, c)) {
        reverse_copy.erase(position, 1);
        str.erase(str.length() - position - 1, 1);
    }
}

void trimChar(string &str, vector<char> chars) {
    char curr_char;
    for (size_t i = 0; i < chars.size(); i++) {
        curr_char = chars[i];
        trimCharLeft(str, curr_char);
        trimCharRight(str, curr_char);
    }
}

void escapeSequence(string &str) {
    char curr_char;
    for (size_t i = 0; i < str.length(); i++) {
        curr_char = str[i];
        if (curr_char == QUOTE) {
            if (i > 0) {
                if (str[i - 1] == ESCAPE) continue;
                str.insert(i - 1, 1, ESCAPE);
            } else {
                str.insert(0, 1, ESCAPE);
            }
        }
    }
}

string pathJoinTmp(string path) {
    string tmppath = filesystem::temp_directory_path();
    if (tmppath[tmppath.length() - 1] == FSLASH) {
        return tmppath + path;
    }

    return tmppath + FSLASH + path;
}

void writeStringToFile(string fpath, string contents) {
    fstream ofile;
    ofile.open(fpath);
    if (!ofile) {
        cout << "\033Error: \033: Failed to write to file, skipped..." << endl;
    }

    ofile << contents;
    ofile.close();
}

string processCodeLineQAndSaveTemp(string code) {
        trimChar(code, cTO_TRIM);
        string tmppath = randomString(10);
        string joined_path = pathJoinTmp(tmppath);
        int new_file = mkstemp64((char *)joined_path.c_str());
        writeStringToFile(joined_path, code);

        return joined_path;
}

string execCommand(string cmd) {
    char buff[512];
    string out;

    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        ERR_EXIT("Problem opening pipe for Python");
    }

    while (fgets(buff, sizeof(buff), pipe) != NULL) {
        out += buff;
    }

    pclose(pipe);
    return out;
}

netAddr_t getAddrType(string addr) {
    smatch re_match_ipv4, re_match_ipv6;
    regex_match(addr, re_match_ipv4, c_IPV4_REGEX);
    regex_match(addr, re_match_ipv6, c_IPV6_REGEX);

    if (re_match_ipv4.size() > 0) {
        return AddrTypeIPV4;
    } else if (re_match_ipv6.size() > 0) {
        return AddrTypeIPV6;
    } else {
        ERR_EXIT("Wrong address given, must be IPV4 or IPV6");
    }
}