#include "includes/slitherbrain.hpp"

namespace slitherbrain
{
    namespace strtools
    {

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

    }
}