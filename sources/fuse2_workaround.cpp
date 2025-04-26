#include "fuse2_workaround.h"

#include <fuse.h>

#include <csignal>

#ifndef _WIN32
#include <fuse_lowlevel.h>

#include "exceptions.h"
#include "logger.h"
#include "myutils.h"

#include <atomic>
#include <thread>
#include <vector>

#include <cerrno>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#else
#include <fuse/winfsp_fuse.h>
#endif

namespace securefs
{

#if defined(_WIN32)
void clean_exit_fuse() { fsp_fuse_signal_handler(SIGINT); }
#else
namespace
{
    int signal_pipefd[2]
        = {-1, -1};    // signal_pipefd[0] is read end, signal_pipefd[1] is write end

    void self_pipe_signal_handler(int sig) noexcept
    {
        // Save and restore errno around the write call, as write can change errno
        int saved_errno = errno;
        char byte = (char)sig;
        (void)write(signal_pipefd[1], &byte, 1);
        errno = saved_errno;    // Restore errno
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
        block_some_signals();
        std::vector<char> buffer(fuse_chan_bufsize(channel));

        DEFER(self_pipe_signal_handler(SIGINT));

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

    void install_signal_handler(int sig)
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = &self_pipe_signal_handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(sig, &sa, nullptr))
        {
            THROW_POSIX_EXCEPTION(errno, "Failed to install signal handler");
        }
    }
}    // namespace
#endif
void clean_exit_fuse() { self_pipe_signal_handler(SIGINT); }
int my_fuse_main(int argc, char** argv, fuse_operations* op, void* user_data)
{
#ifdef _WIN32
    return fuse_main(argc, argv, op, user_data);
#else
    char* mountpoint;
    int multithreaded;
    if (pipe(signal_pipefd) < 0)
    {
        THROW_POSIX_EXCEPTION(errno, "pipe");
    }
    if (fcntl(signal_pipefd[1], F_SETFL, O_NONBLOCK) < 0)
    {
        THROW_POSIX_EXCEPTION(errno, "fcntl");
    }

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

    install_signal_handler(SIGINT);
    install_signal_handler(SIGTERM);
    install_signal_handler(SIGHUP);

    std::thread waiter(
        [&]()
        {
            while (true)
            {
                char b;
                if (read(signal_pipefd[0], &b, 1) > 0)
                {
                    break;
                }
                if (errno == EINTR)
                {
                    continue;
                }
                WARN_LOG("Failed to read from self pipe: %s",
                         OSService::stringify_system_error((errno)));
                continue;
            }
            fuse_session_exit(session);

            for (auto&& w : workers)
            {
                pthread_cancel(w.native_handle());
            }
        });
    waiter.join();

    for (auto&& w : workers)
    {
        w.join();
    }

    return error_code;
#endif
}
}    // namespace securefs
