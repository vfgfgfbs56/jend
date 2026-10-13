cmake_minimum_required(VERSION 3.20)
project(jend_gguf_cpu_worker LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Protocol-only CI compile has zero external model/native dependency.
option(JEND_BUILD_EXPERIMENTAL_LLAMA "Build experimental real llama.cpp CPU worker" OFF)
set(JEND_PINNED_LLAMA_SHA "45451c366d4256f94fbc8845645e31a6b9155054")
add_executable(jend-gguf-cpu-worker worker.cpp)
# MSVC cannot compile GNU-only -Wall/-Wextra/-Werror flags. Keep
# warnings strict, but select the compiler's real flag vocabulary.
if(MSVC)
    target_compile_options(jend-gguf-cpu-worker PRIVATE /W4 /WX)
else()
    target_compile_options(jend-gguf-cpu-worker PRIVATE -Wall -Wextra -Werror)
endif()
if(JEND_BUILD_EXPERIMENTAL_LLAMA)
    set(JEND_LLAMA_SOURCE "" CACHE PATH "Pinned local llama.cpp source directory")
    if(NOT EXISTS "${JEND_LLAMA_SOURCE}/include/llama.h")
        message(FATAL_ERROR "Set JEND_LLAMA_SOURCE to a local pinned llama.cpp checkout")
    endif()
    find_package(Git REQUIRED)
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${JEND_LLAMA_SOURCE}" rev-parse HEAD
        OUTPUT_VARIABLE LLAMA_HEAD
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE GIT_STATUS
    )
    if(NOT GIT_STATUS EQUAL 0 OR NOT LLAMA_HEAD STREQUAL JEND_PINNED_LLAMA_SHA)
        message(FATAL_ERROR "llama.cpp source must be exactly pinned at ${JEND_PINNED_LLAMA_SHA}")
    endif()
    set(LLAMA_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(LLAMA_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(LLAMA_BUILD_SERVER OFF CACHE BOOL "" FORCE)
    set(GGML_METAL OFF CACHE BOOL "" FORCE)
    set(GGML_CUDA OFF CACHE BOOL "" FORCE)
    set(GGML_VULKAN OFF CACHE BOOL "" FORCE)
    add_subdirectory("${JEND_LLAMA_SOURCE}" "${CMAKE_BINARY_DIR}/pinned-llama" EXCLUDE_FROM_ALL)
    target_link_libraries(jend-gguf-cpu-worker PRIVATE llama)
    target_include_directories(jend-gguf-cpu-worker PRIVATE "${JEND_LLAMA_SOURCE}/include")
    target_compile_definitions(jend-gguf-cpu-worker PRIVATE JEND_WITH_LLAMA=1)
endif()
