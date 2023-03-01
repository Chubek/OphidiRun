#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <seccomp.h>
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

using namespace std;

#define NEWLINE "\n"
#define QUOTE '"'
#define ESCAPE '\\'
#define FSLASH '/'
#define ALNUM 25
#define TMPSZ 10

const vector<char> cTO_TRIM = { '\0', ' ', '\r', '\n', ';', '\t' };
const vector<char> cUPPERCASE = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'M', 'N', 'O', 'P', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};


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
        cout << "\033Error :\033 Problem opening pipe for Python" << endl;
        exit(1);
    }

    while (fgets(buff, sizeof(buff), pipe) != NULL) {
        out += buff;
    }

    pclose(pipe);
    return out;
}

