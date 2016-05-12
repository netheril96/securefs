#define CATCH_CONFIG_RUNNER 1
#include "catch.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char** argv)
{
    int rc = ::mkdir("tmp", 0755);
    if (rc < 0 && errno != EEXIST)
    {
        perror("Failure to create directory 'tmp'");
        return rc;
    }
    Catch::Session s;
    rc = s.run(argc, argv);
    return rc;
}
