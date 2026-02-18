cmake_minimum_required(VERSION 4.0.0)

project(X25519 C)

include_directories(/home/peter/Developer/Personal/CEdev/include)

add_executable(new_target src/main.c
        src/x25519.h
)
