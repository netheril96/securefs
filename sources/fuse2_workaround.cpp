#include "fuse2_workaround.h"
#include "logger.h"
#include "myutils.h"

#include <fuse/fuse.h>
#ifndef _WIN32
#include <csignal>
#include <fuse/fuse_lowlevel.h>
#include <pthread.h>

#include <future>
#include <thread>
#include <vector>
#endif

namespace securefs
{

#ifndef _WIN32
namespace
{
    void block_some_signals()
    {
        sigset_t newset;
        sigemptyset(&newset);
        sigaddset(&newset, SIGTERM);
        sigaddset(&newset, SIGINT);
        sigaddset(&newset, SIGHUP);
        sigaddset(&newset, SIGQUIT);
        pthread_sigmask(SIG_BLOCK, &newset, nullptr);
    }

    int worker_loop(fuse_session* session, fuse_chan* channel)
    {
        block_some_signals();
        std::vector<char> buffer(fuse_chan_bufsize(channel));

        while (!fuse_session_exited(session))
        {
            fuse_buf fbuf{};
            fbuf.mem = buffer.data();
            fbuf.size = buffer.size();

            int res;
            pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr);
            res = fuse_session_receive_buf(session, &fbuf, &channel);
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr);
            if (res == -EINTR)
                continue;
            if (res < 0)
            {
                ERROR_LOG(
                    "fuse_session_receive_buf failed with error code %d, exiting abnormally...",
                    res);
                fuse_session_exit(session);
                return res;
            }
            if (res == 0)
            {
                return 0;
            }
            fuse_session_process_buf(session, &fbuf, channel);
        }
        return 0;
    }
}    // namespace
#endif

int my_fuse_main(int argc, char** argv, fuse_operations* op, void* user_data)
{
#ifdef _WIN32
    return fuse_main(argc, argv, op, user_data);
#else
    char* mountpoint;
    int multithreaded;

    auto fuse = fuse_setup(argc, argv, op, sizeof(*op), &mountpoint, &multithreaded, user_data);
    if (fuse == nullptr)
        return 1;
    DEFER(fuse_teardown(fuse, mountpoint));

    if (int res = fuse_start_cleanup_thread(fuse); res != 0)
    {
        return 2;
    }
    DEFER(fuse_stop_cleanup_thread(fuse));

    auto session = fuse_get_session(fuse);
    auto channel = fuse_session_next_chan(session, nullptr);
    if (!channel)
    {
        return 3;
    }

    std::vector<std::future<int>> workers(multithreaded ? std::thread::hardware_concurrency() * 2
                                                        : 1);
    for (auto&& w : workers)
    {
        w = std::async(std::launch::async, [=]() { return worker_loop(session, channel); });
    }
    std::vector<int> results;
    results.reserve(workers.size());
    for (auto&& w : workers)
    {
        results.push_back(w.get());
    }
    for (int rc : results)
    {
        if (rc)
        {
            return rc;
        }
    }
    return 0;
#endif
}
}    // namespace securefs
