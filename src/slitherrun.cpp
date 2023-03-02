#include "includes/slitherbrain.hpp"

int main(int argc, char **argv)
{
    std::vector<std::string> unallowed_syscalls;
    std::string pythonpath, scriptpath;

    for (int i = 3; i < argc; i++)
    {
        unallowed_syscalls.push_back(std::string(argv[i]));
    }

    pythonpath = std::string(argv[1]);
    scriptpath = std::string(argv[2]);

    slitherbrain::process::sandboxProcess(unallowed_syscalls);
    std::string command = pythonpath + " " + scriptpath;
    std::string exec_result = slitherbrain::process::execCommand(command);
    slitherbrain::filetools::removeScriptFile(scriptpath);

    std::cout << exec_result << std::endl;
}