cmake_minimum_required(VERSION 3.21)
project(microrl-remaster VERSION 2.5.0 DESCRIPTION "microrl-remaster")
add_library(microrl-remaster STATIC microrl-remaster/src/microrl/microrl.c)
target_include_directories(microrl-remaster
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/microrl-remaster/src/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/microrl-remaster/src/include/microrl
)