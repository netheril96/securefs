#include "commands.h"
#include <clocale>

int main(int argc, char** argv)
{
    setlocale(LC_ALL, "");
    return securefs::commands_main(argc, argv);
}
