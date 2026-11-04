# Processor Module: lm32
ida_add_procmod(lm32
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        lm32.hpp
        ins.hpp
)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cfg/LM32.cfg")
    copy_cfg(lm32 ${CMAKE_CURRENT_SOURCE_DIR}/cfg/LM32.cfg)
endif()

# Deploy procmod and configuration to IDA user directory (%APPDATA%/Hex-Rays/IDA Pro)
if(DEFINED ENV{APPDATA})
    set(IDA_USER_DIR "$ENV{APPDATA}/Hex-Rays/IDA Pro")

    add_custom_command(TARGET lm32 POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${IDA_USER_DIR}/procs"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:lm32>" "${IDA_USER_DIR}/procs/$<TARGET_FILE_NAME:lm32>"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${IDA_USER_DIR}/cfg"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/cfg/LM32.cfg" "${IDA_USER_DIR}/cfg/LM32.cfg"
        COMMENT "Deploying LM32 procmod and configuration to IDA Pro user directory"
    )
endif()
