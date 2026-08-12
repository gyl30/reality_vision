#ifndef REALITY_VISION_SERVICE_HPP
#define REALITY_VISION_SERVICE_HPP

#include "config.hpp"

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

namespace boost::asio
{
class io_context;
}

namespace rv::app
{

class listener_service;

class service
{
   public:
    explicit service(config configuration);

    void startup();

   private:
    void shutdown();

    config configuration_;
    std::vector<std::shared_ptr<boost::asio::io_context>> contexts_;
    std::vector<std::shared_ptr<listener_service>> listener_services_;
    std::vector<std::thread> workers_;
    std::atomic_bool stopping_{false};
};

}    // namespace rv::app

#endif    // REALITY_VISION_SERVICE_HPP
