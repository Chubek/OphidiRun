#include "../includes/slitherbrain.hpp"

namespace slitherbrain
{
    namespace process
    {
        string runSlitherRunProcess(string slitherrun_path, string python_path, string disallowed_calls, string code)
        {
            string tmp_filep = slitherbrain::filetools::processCodeAndSaveTemp(code);
            vector<string> command_vec = {slitherrun_path, python_path, tmp_filep, disallowed_calls};
            string command = slitherbrain::strtools::joinStrVector(command_vec, " ");

            string result = execCommand(command);
            return result;
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

        void sandboxProcess(vector<string> to_disallow)
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

    }
}