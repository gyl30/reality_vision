#ifndef REALITY_VISION_SERVICE_HPP
#define REALITY_VISION_SERVICE_HPP

#include <thread>
#include "config.hpp"

namespace rv::app
{

class service
{
   public:
    explicit service(config configuration);

   public:
    void run();

   private:
    void spawn_server(boost::asio::io_context& context, boost::asio::awaitable<void> server, const std::string& server_name);

    void server_exception(const std::string& server_name, const std::exception_ptr& exception);

   private:
    config configuration_;
    std::vector<std::thread> workers_;
    std::vector<std::shared_ptr<boost::asio::io_context>> contexts_;
};

}    // namespace rv::app

#endif    // REALITY_VISION_SERVICE_HPP
