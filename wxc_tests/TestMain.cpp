#include "pch.h"

#include "gtest/gtest.h"

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    // Uncomment to run a specific test case or filter
    //::testing::GTEST_FLAG(filter) = "ConfigurationParserTest.Base64MinimalConfig";
    return RUN_ALL_TESTS();
}
