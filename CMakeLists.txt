cmake_minimum_required(VERSION 3.10)
project(UserspaceStack CXX)

# Set the C++ standard to 20 for std::span and other modern features
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Tell CMake where to find your .h / .hpp files
include_directories(include)

# Define the source files for the project
set(SOURCES
    src/main.cpp
    src/tapinterface.cpp
    src/networkstack.cpp
)

# Create the executable
# The name "NetworkStack" will be the name of the final compiled binary
add_executable(NetworkStack ${SOURCES})

# (Optional) Add extra compiler warnings to help catch bugs early
target_compile_options(NetworkStack PRIVATE -Wall -Wextra)