#
# Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

FindOpenSSL()
message(STATUS "Current list dir: ${CMAKE_CURRENT_LIST_DIR}")
#set(OPENSSL_ROOT_DIR 

find_package(camkes-tool REQUIRED)
find_package(global-components REQUIRED)
find_package(sel4_projects_libs REQUIRED)
find_package(openssl REQUIRED)

set(KernelRootCNodeSizeBits 17 CACHE STRING "")

camkes_tool_setup_camkes_build_environment()

sel4_projects_libs_import_libraries()

function(includeGlobalComponents)
    global_components_import_project()
endfunction()

project(hello-world C)

DeclareCAmkESComponent(HelloWorld SOURCES components/HelloWorld/src/hello-world.c LIBS sel4bench)
DeclareCAmkESRootserver(hello-world.camkes)

GenerateCAmkESRootserver()
