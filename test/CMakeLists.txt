include(CMTest)
cm_find_package(Boost COMPONENTS unit_test_framework)
cm_test_link_libraries(
        crypto3::algebra
        crypto3::multiprecision
        crypto3::pubkey

        ${Boost_LIBRARIES})

cm_test(NAME votes_test SOURCES votes_test.cpp)
target_include_directories(votes_test PRIVATE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                           ${Boost_INCLUDE_DIRS})

set_target_properties(votes_test PROPERTIES CXX_STANDARD 14)
target_compile_definitions(votes_test PRIVATE BOOST_TEST_DYN_LINK)
