if(CIRCUIT_ASSEMBLY_OUTPUT)
    set(extension ll)
    set(format_option -S)
else()
    set(extension bc)
    set(format_option -c)
endif()

set(CMAKE_C_COMPILER_TARGET "assigner")
set(CMAKE_CXX_COMPILER_TARGET "assigner")

set(CMAKE_LIBRARY_ARCHITECTURE "")

set(CMAKE_C_FLAGS "-Xclang -no-opaque-pointers -Xclang -fpreserve-vec3-type -emit-llvm -O1 ${format_option}")
set(CMAKE_CXX_FLAGS "-Xclang -no-opaque-pointers -Xclang -fpreserve-vec3-type -emit-llvm -O1 ${format_option}")

set(CMAKE_C_OUTPUT_EXTENSION "${extension}")
set(CMAKE_CXX_OUTPUT_EXTENSION "${extension}")

set(COMPILE_DEFINITIONS "-D __ZKLLVM__")

list(APPEND LINK_FLAGS "-opaque-pointers=0")

if(CIRCUIT_ASSEMBLY_OUTPUT)
    list(APPEND LINK_FLAGS "-S")
endif()