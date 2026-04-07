cmake_minimum_required(VERSION 3.20)
project(ERDPS_Driver LANGUAGES C CXX)

# --- WDK Configuration ---
# You must have the Windows Driver Kit (WDK) installed!
if(NOT DEFINED ENV{WDKContentRoot})
    message(FATAL_ERROR "WDKContentRoot environment variable not found. Please install the Windows Driver Kit.")
endif()

set(WDK_ROOT $ENV{WDKContentRoot})
set(WDK_INC "${WDK_ROOT}/Include/10.0.26100.0") # Adjust version if needed
set(WDK_LIB "${WDK_ROOT}/Lib/10.0.26100.0")

# --- Compiler Flags (Kernel Mode) ---
add_definitions(-D_X86_=1 -Di386=1 -DSTD_CALL -DCONDITION_HANDLING=1 -DNT_UP=1 -DNT_INST=0 -DWIN32=100 -D_NT1X_=100 -DWINNT=1 -D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00 -D_WIN32_IE=0x0A00)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Kernel /wd4603 /wd4627 /wd4986 /wd4987 /QSpectre")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Kernel /QSpectre")

# --- Include Directories ---
include_directories(
    "${WDK_INC}/km"
    "${WDK_INC}/shared"
    "${WDK_INC}/km/crt"
    "include" # Our shared_def.h
)

# --- The Driver Binary ---
add_executable(erdps_driver
    sources/minifilter.cpp
    # Add other sources here if you split the file later
)

# Rename .exe to .sys
set_target_properties(erdps_driver PROPERTIES SUFFIX ".sys")

# --- Linker Flags (The Magic) ---
# We must link against FltMgr.lib (Filter Manager) and NtosKrnl.lib
target_link_libraries(erdps_driver
    "${WDK_LIB}/km/x64/FltMgr.lib"
    "${WDK_LIB}/km/x64/ntoskrnl.lib"
    "${WDK_LIB}/km/x64/hal.lib"
)

# Set Entry Point (DriverEntry is standard, but for C++ we often use GsDriverEntry)
set_target_properties(erdps_driver PROPERTIES LINK_FLAGS "/DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE /INTEGRITYCHECK")

message(STATUS "Ready to build ERDPS Driver. Ensure you run this in a Visual Studio Command Prompt.")
