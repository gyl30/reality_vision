#ifndef REALITY_VISION_SERVICE_HPP
#define REALITY_VISION_SERVICE_HPP

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

#include "config.hpp"

namespace boost::asio
{
class io_context;
}

namespace rv::app
{

class proxy_service;

class service
{
   public:
    explicit service(config configuration);

    void startup();

   private:
    void shutdown();

    config configuration_;
    std::vector<std::shared_ptr<boost::asio::io_context>> contexts_;
    std::vector<std::shared_ptr<proxy_service>> proxy_services_;
    std::vector<std::thread> workers_;
    std::atomic_bool stopping_{false};
};

}    // namespace rv::app

#endif    // REALITY_VISION_SERVICE_HPP
