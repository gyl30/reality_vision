#include "config.hpp"
#include "service.hpp"
#include "protocol_tests.hpp"

#include <spdlog/spdlog.h>

int main(int argc, char* argv[])
{
    spdlog::set_pattern("%Y-%m-%d %H:%M:%S.%e %^%l%$ %v");

    const auto configuration = rv::app::parse_config(argc, argv);
    if (!configuration)
    {
        return static_cast<int>(configuration.error());
    }
    if (configuration->self_test)
    {
        return rv::testing::run_protocol_tests();
    }
    rv::app::service(*configuration).startup();
    return 0;
}
