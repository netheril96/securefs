#ifndef THREAD_POOL_HPP
#define THREAD_POOL_HPP

#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <iostream>

struct thread_pool {
    using job = std::function<void()>;

private:

    std::vector<std::queue<job>>                          work_queues;
    std::vector<std::unique_ptr<std::mutex>>              locks;
    std::vector<std::unique_ptr<std::condition_variable>> condvars;
    std::vector<std::unique_ptr<std::thread>>             threads;

    std::mutex job_done_lock;
    std::condition_variable job_done;

    std::atomic<size_t> rr_ind;

    std::atomic<size_t> active_count;

    bool active;

public:
    thread_pool(size_t num_threads) {
        active = true;
        rr_ind.store(0);
        active_count.store(0);

        work_queues.resize(num_threads);
        threads.resize(num_threads);
        locks.resize(num_threads);
        condvars.resize(num_threads);

        for(size_t i=0; i < num_threads; ++i) {
            locks[i].reset(new std::mutex());
            condvars[i].reset(new std::condition_variable());

            threads[i].reset(new std::thread(
                        [i,this]() {
                while(active) {
                    job f = []() {};
                    {
                        std::unique_lock<std::mutex> l(*locks[i]);

                        while(work_queues[i].empty() && active) {
                            condvars[i]->wait(l);
                        }
                        if(!active) { break; }
                        ++active_count;

                        f = work_queues[i].front();
                        work_queues[i].pop();
                        /* std::cout << "Thread " << i << ": tick\n"; */
                    }
                    f();
                    --active_count;
                    job_done.notify_all();
                }
            }));

        }
    }

    ~thread_pool() {
        active = false;
        for(auto& cv: condvars) {
            cv->notify_all();
        }
        for(auto& t: threads) {
            t->join();
        }
    }

    void add_job(job j) {
        size_t i = (rr_ind++)%threads.size();
        /* std::cout << "Adding to queue " << i << std::endl; */
        {
            std::lock_guard<std::mutex> l(*locks[i]);

            work_queues[i].push(j);
        }
        condvars[i]->notify_all();
    }

    bool done() {
        if(!active_count.load()) {
            bool anything_queued = false;
            for(const auto& q: work_queues) {
                if(!q.empty()) {
                    anything_queued = true;
                }
            }
            if(!anything_queued) {
                return true;
            }
        }
        return false;
    }

    bool wait() {
        if(done()) return true;

        {
            std::unique_lock<std::mutex> l(job_done_lock);
            job_done.wait_for(l,std::chrono::milliseconds(100));
        }
        return done();
    }
    void barrier() {
        size_t i = 0;
        for(;wait();++i) { }
    }
};

#endif

