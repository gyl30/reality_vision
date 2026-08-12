#ifndef REALITY_VISION_SERVICE_HPP
#define REALITY_VISION_SERVICE_HPP

#include "config.hpp"

namespace rv::app
{

class service
{
   public:
    explicit service(config configuration);

    int run();

   private:
    config configuration_;
};

}    // namespace rv::app

#endif    // REALITY_VISION_SERVICE_HPP
