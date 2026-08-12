#ifndef REALITY_VISION_LISTENER_SERVICE_HPP
#define REALITY_VISION_LISTENER_SERVICE_HPP

namespace rv::app
{

class listener_service
{
   public:
    virtual ~listener_service() = default;

    virtual void startup() = 0;
};

}    // namespace rv::app

#endif    // REALITY_VISION_LISTENER_SERVICE_HPP
