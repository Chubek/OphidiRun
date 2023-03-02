#include "includes/slitherbrain.hpp"

volatile sig_atomic_t sigc;

void sighandle(int signum)
{
    sigc = 1;
}

int main(int argc, char **argv)
{
    signal(SIGINT, sighandle);
    slitherbrain::args::parseArgsAndRun(argc, argv, sigc);
}