#include "fuse2_workaround.h"

#include <fuse.h>

#ifndef _WIN32
#include <fuse_lowlevel.h>

#include "exceptions.h"
#include "lock_guard.h"
#include "logger.h"
#include "myutils.h"

#include <absl/synchronization/mutex.h>

#include <cerrno>
#include <csignal>
#include <pthread.h>

#include <atomic>
#include <thread>
#include <vector>
#endif

namespace securefs
{

#if defined(_WIN32)
#else
namespace
{
    absl::Mutex kSignalEndMutex{absl::kConstInit};
    bool isExiting ABSL_GUARDED_BY(kSignalEndMutex);

    void markExiting()
    {
        LockGuard<absl::Mutex> lg(kSignalEndMutex);
        isExiting = true;
    }

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

    void worker_loop(fuse_session* session, fuse_chan* channel, std::atomic<int>* error_code)
    {
        std::vector<char> buffer(fuse_chan_bufsize(channel));

        DEFER(markExiting());

        while (!fuse_session_exited(session))
        {
            {
                LockGuard<absl::Mutex> lg(kSignalEndMutex);
                if (isExiting)
                {
                    return;
                }
            }
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
                *error_code = res;
                return;
            }
            if (res == 0)
            {
                return;
            }
            fuse_session_process_buf(session, &fbuf, channel);
        }
    }
}    // namespace
#endif

int my_fuse_main(int argc, char** argv, fuse_operations* op, void* user_data)
{
#if defined(_WIN32)
    return fuse_main(argc, argv, op, user_data);
#else
    char* mountpoint;
    int multithreaded;
    block_some_signals();

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

    std::atomic<int> error_code{};
    std::vector<std::thread> workers(multithreaded ? std::thread::hardware_concurrency() : 1);
    for (auto&& w : workers)
    {
        w = std::thread(worker_loop, session, channel, &error_code);
    }

    std::thread signal_handler(
        []()
        {
            sigset_t newset;
            sigemptyset(&newset);
            sigaddset(&newset, SIGTERM);
            sigaddset(&newset, SIGINT);
            sigaddset(&newset, SIGHUP);
            sigaddset(&newset, SIGQUIT);

            int sig;
            while (true)
            {
                int rc = sigwait(&newset, &sig);
                if (rc < 0)
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    else
                    {
                        THROW_POSIX_EXCEPTION(errno, "sigwait");
                    }
                }
                markExiting();
                return;
            }
        });

    std::thread waiter(
        [&]()
        {
            {
                LockGuard<absl::Mutex> lg(kSignalEndMutex);
                kSignalEndMutex.Await(absl::Condition(&isExiting));
            }

            fuse_session_exit(session);

            for (auto&& w : workers)
            {
                pthread_cancel(w.native_handle());
            }
        });
    signal_handler.detach();
    waiter.join();

    for (auto&& w : workers)
    {
        w.join();
    }

    return error_code;
#endif
}
}    // namespace securefs
