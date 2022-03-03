#
# Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

find_package(camkes-tool REQUIRED)
find_package(global-components REQUIRED)
find_package(sel4_projects_libs REQUIRED)

set(KernelRootCNodeSizeBits 17 CACHE STRING "")

camkes_tool_setup_camkes_build_environment()

sel4_projects_libs_import_libraries()

function(includeGlobalComponents)
    global_components_import_project()
endfunction()

project(hello-world C)

set(projects_dir "${CMAKE_SOURCE_DIR}/../../projects")
set(crypto_path "${projects_dir}/crypto")

DeclareCAmkESComponent(
    HelloWorld 
    SOURCES
        components/HelloWorld/src/hello-world.c
        ${crypto_path}/src/hashes/sha3.c
        ${crypto_path}/src/hashes/sha3_test.c
        ${crypto_path}/src/misc/compare_testvector.c
        ${crypto_path}/src/misc/crypt/crypt_argchk.c
    INCLUDES
        ${crypto_path}/src/headers
)
DeclareCAmkESRootserver(hello-world.camkes)

GenerateCAmkESRootserver()
