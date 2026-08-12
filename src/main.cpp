#include "config.hpp"
#include "protocol_tests.hpp"
#include "service.hpp"

#include <spdlog/spdlog.h>

#include <exception>

int main(int argc, char* argv[])
{
    spdlog::set_pattern("%Y-%m-%d %H:%M:%S.%e %^%l%$ %v");

    try
    {
        const auto configuration = rv::app::parse_config(argc, argv);
        if (!configuration)
        {
            return static_cast<int>(configuration.error());
        }
        if (configuration->self_test)
        {
            return rv::testing::run_protocol_tests();
        }
        return rv::app::service(*configuration).run();
    }
    catch (const std::exception& error)
    {
        spdlog::error("unexpected fatal exception: {}", error.what());
        return 1;
    }
}
