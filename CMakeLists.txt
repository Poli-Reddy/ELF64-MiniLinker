cmake_minimum_required(VERSION 3.16)
project(ELF64MiniLinker VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(elf64-mini src/elf64_mini_linker.cpp)

if(MSVC)
    target_compile_options(elf64-mini PRIVATE /W4 /permissive-)
else()
    target_compile_options(elf64-mini PRIVATE -Wall -Wextra -Wpedantic)
endif()

include(CTest)

if(BUILD_TESTING)
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_test(
            NAME elf64-mini-fixtures
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.py $<TARGET_FILE:elf64-mini>
        )
        set_tests_properties(elf64-mini-fixtures PROPERTIES TIMEOUT 120)
    else()
        message(WARNING "Python 3 was not found; generated-ELF fixture tests are disabled")
    endif()

    # Optional real-compiler smoke test.  It needs a host compiler that emits
    # ELF objects and a working bash.  Skip it on Windows and on Apple, whose
    # cc produces Mach-O rather than ELF.
    find_program(BASH_EXECUTABLE NAMES bash)
    find_program(ELF_C_COMPILER NAMES cc gcc clang)
    if(BASH_EXECUTABLE AND ELF_C_COMPILER AND UNIX AND NOT APPLE)
        add_test(
            NAME elf64-mini-real-objects
            COMMAND ${BASH_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_link.sh
                    $<TARGET_FILE:elf64-mini> ${CMAKE_CURRENT_SOURCE_DIR}/tests ${ELF_C_COMPILER}
        )
        set_tests_properties(elf64-mini-real-objects PROPERTIES TIMEOUT 120)
    endif()
endif()
