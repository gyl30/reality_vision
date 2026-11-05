#ifndef REALITY_VISION_SERVICE_HPP
#define REALITY_VISION_SERVICE_HPP

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

#include "config.hpp"
#include "tun_inbound.hpp"

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

    // 启动失败时返回 false；成功时阻塞到所有 worker 退出。
    [[nodiscard]] bool startup();

   private:
    void shutdown();

    config configuration_;
    std::vector<std::shared_ptr<boost::asio::io_context>> contexts_;
    std::vector<std::shared_ptr<proxy_service>> proxy_services_;
    std::shared_ptr<tun::tun_inbound> tun_inbound_;
    std::vector<std::thread> workers_;
    std::atomic_bool stopping_{false};
};

}    // namespace rv::app

#endif    // REALITY_VISION_SERVICE_HPP
