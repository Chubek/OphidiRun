#include "includes/slitherbrain.hpp"

namespace slitherbrain
{
    namespace utils
    {
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
                char new_char = slitherbrain::consts::cUPPERCASE[new_rand];
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

    }
}