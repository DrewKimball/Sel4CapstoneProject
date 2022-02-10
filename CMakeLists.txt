#
# Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

include(settings.cmake)

project(capstone C CXX ASM)

add_subdirectory(apps/hello-world)

include(simulation)
if(KernelSel4ArchX86_64)
    SetSimulationScriptProperty(MEM_SIZE "3G")
endif()
if(KernelPlatformQEMUArmVirt)
    SetSimulationScriptProperty(MEM_SIZE "2G")
endif()

if(SIMULATION)
    GenerateSimulateScript()
endif()
