#include "fuse2_workaround.h"

#include <fuse.h>

#ifndef _WIN32
#include <fuse_lowlevel.h>

#include "exceptions.h"
#include "logger.h"
#include "myutils.h"

#include <cerrno>
#include <csignal>
#include <pthread.h>
#include <semaphore.h>

#include <atomic>
#include <thread>
#include <vector>
#endif

namespace securefs
{

#if defined(_WIN32) || defined(__APPLE__)
#else
namespace
{
    // Wrapper around POSIX semaphore. Needed because it is an async signal safe communication
    // mechanism.
    class Semaphore
    {
    public:
        Semaphore()
        {
            if (sem_init(&s_, 0, 0) < 0)
                THROW_POSIX_EXCEPTION(errno, "Failed to initialize semaphore");
        }
        ~Semaphore() { sem_destroy(&s_); }
        DISABLE_COPY_MOVE(Semaphore);

        void wait()
        {
            while (true)
            {
                int rc = sem_wait(&s_);
                if (rc < 0 && errno == EINTR)
                {
                    continue;
                }
                if (rc < 0)
                {
                    THROW_POSIX_EXCEPTION(errno, "sem_wait fails");
                }
                return;
            }
        }
        void post()
        {
            if (sem_post(&s_) < 0)
            {
                THROW_POSIX_EXCEPTION(errno, "sem_post fails");
            }
        }

    private:
        sem_t s_;
    };

    Semaphore global_semaphore;

    void signal_handler(int) { global_semaphore.post(); }

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

        DEFER(global_semaphore.post());

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
        sa.sa_handler = &signal_handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(sig, &sa, nullptr))
        {
            THROW_POSIX_EXCEPTION(errno, "Failed to install signal handler");
        }
    }
}    // namespace
#endif

int my_fuse_main(int argc, char** argv, fuse_operations* op, void* user_data)
{
#if defined(_WIN32) || defined(__APPLE__)
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

    std::atomic<int> error_code;
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
            block_some_signals();
            global_semaphore.wait();
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
