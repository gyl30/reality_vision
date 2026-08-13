#ifndef REALITY_VISION_PROXY_SERVICE_HPP
#define REALITY_VISION_PROXY_SERVICE_HPP

namespace rv::app
{

class proxy_service
{
   public:
    virtual ~proxy_service() = default;

    virtual void startup() = 0;
};

}    // namespace rv::app

#endif    // REALITY_VISION_PROXY_SERVICE_HPP
