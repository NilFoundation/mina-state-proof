add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/crypto3")

cm_project(state_proof WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES ASM C CXX)

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME})

add_executable(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_account_inclusion
        account/account_path.cpp)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_account_inclusion PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>)

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_account_inclusion PUBLIC
        crypto3::algebra
        crypto3::block
        crypto3::codec
        crypto3::containers
        crypto3::hash
        crypto3::kdf
        crypto3::mac
        marshalling::core
        marshalling::crypto3_algebra
        marshalling::crypto3_multiprecision
        marshalling::crypto3_zk
        crypto3::math
        crypto3::modes
        crypto3::multiprecision
        crypto3::passhash
        crypto3::pbkdf
        crypto3::threshold
        crypto3::pkpad
        crypto3::pubkey
        crypto3::random
        crypto3::stream
        crypto3::vdf
        crypto3::zk

        ${Boost_LIBRARIES})

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CMAKE_PROJECT_NAME}_account_inclusion PROPERTIES
        LINKER_LANGUAGE CXX
        EXPORT_NAME ${CMAKE_PROJECT_NAME}
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED TRUE)