#include "myutils.h"
#include "exceptions.h"
#include "logger.h"
#include "platform.h"

#include <absl/strings/str_format.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <string.h>
#include <system_error>
#include <time.h>
#include <vector>

namespace securefs
{
static void find_ids_helper(const std::string& current_dir,
                            std::unordered_set<id_type, id_hash>& result)
{
    id_type id;
    std::string hex(id_type::size() * 2, 0);
    OSService::recursive_traverse_callback callback
        = [&id, &result, &hex](StringRef dir, StringRef name) -> bool
    {
        if (name == "." || name == "..")
            return true;
        if (name.ends_with(".meta"))
        {
            std::string total_name = dir + "/" + name.substr(0, name.size() - strlen(".meta"));
            hex.assign(hex.size(), 0);
            ptrdiff_t i = hex.size() - 1, j = total_name.size() - 1;
            while (i >= 0 && j >= 0)
            {
                char namechar = total_name[j];
                if ((namechar >= '0' && namechar <= '9') || (namechar >= 'a' && namechar <= 'f'))
                {
                    hex[i] = namechar;
                    --i;
                }
                else if (namechar != '/' && namechar != '\\')
                {
                    throw_runtime_error(absl::StrFormat(
                        "File \"%s\" has extension .meta, but not a valid securefs "
                        "meta filename. Please cleanup the underlying storage first.",
                        total_name));
                }
                --j;
            }
            parse_hex(hex, id.data(), id.size());
            result.insert(id);
        }
        return true;
    };

    OSService::get_default().recursive_traverse(current_dir, callback);
}

std::unordered_set<id_type, id_hash> find_all_ids(const std::string& basedir)
{
    std::unordered_set<id_type, id_hash> result;
    find_ids_helper(basedir, result);
    return result;
}

std::string get_user_input_until_enter()
{
    std::string result;
    while (true)
    {
        int ch = getchar();
        if (ch == EOF)
        {
            return result;
        }
        if (ch == '\r' || ch == '\n')
        {
            while (!result.empty() && isspace(static_cast<unsigned char>(result.back())))
                result.pop_back();
            result.push_back('\n');
            return result;
        }
        else if (!result.empty() || !isspace(ch))
        {
            result.push_back(static_cast<unsigned char>(ch));
        }
    }
    return result;
}

void respond_to_user_action(
    const absl::flat_hash_map<std::string, std::function<void(void)>>& actionMap)
{
    while (true)
    {
        std::string cmd = get_user_input_until_enter();
        if (cmd.empty() || cmd.back() != '\n')
        {
            // EOF
            return;
        }
        auto it = actionMap.find(cmd);
        if (it == actionMap.end())
        {
            puts("Invalid command");
            continue;
        }
        it->second();
        break;
    }
}

size_t popcount(const byte* data, size_t size) noexcept
{
    static const size_t TABLE[256]
        = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3,
           4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4,
           4, 5, 4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4,
           5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5,
           4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2,
           3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5,
           5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4,
           5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6,
           4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8};
    size_t res = 0;
    for (size_t i = 0; i < size; ++i)
        res += TABLE[data[i]];
    return res;
}

void warn_if_key_not_random(const byte* key, size_t size, const char* file, int line) noexcept
{
    size_t pp = popcount(key, size);
    if (pp <= size || pp >= 7 * size)
    {
        WARN_LOG("Encounter a key with %g%% bits all ones, therefore not \"random enough\". "
                 "Please report as a bug (%s:%d).",
                 double(pp) / double(8 * size) * 100.0,
                 file,
                 line);
    }
}
}    // namespace securefs
