#include "../includes/slitherbrain.hpp"

namespace slitherbrain
{
    namespace args
    {
        void parseArgsAndRun(int argc, char **argv, volatile sig_atomic_t &sigc)
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
            disallowed_calls = slitherbrain::utils::readConfigFile(config_path);

            slitherbrain::net::serveHttpForever(ip, port_int, slitherrun_path, python_path, disallowed_calls, sigc);
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
    }
}