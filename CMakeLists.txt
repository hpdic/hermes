cmake_minimum_required(VERSION 3.10)
project(hermes)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add OpenFHE dependency (assumed installed system-wide)
find_package(OpenFHE REQUIRED)

# Add submodules
add_subdirectory(src/singular)
add_subdirectory(src/crypto)
add_subdirectory(src/pack) 
