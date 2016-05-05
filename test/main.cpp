#define CATCH_CONFIG_RUNNER 1
#include "catch.hpp"

#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>

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
