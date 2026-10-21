# Standalone rendering regressions; does not require a Wireshark build.
cmake_minimum_required(VERSION 3.21)
project(wireshark_qt_style_tests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Widgets)
get_filename_component(WIRESHARK_SOURCE_DIR "../.." ABSOLUTE)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/config.h" "")

add_executable(packet_list_style_test
    packet_list_style_test.cpp
    "${WIRESHARK_SOURCE_DIR}/ui/qt/utils/theme_styler.cpp"
    "${WIRESHARK_SOURCE_DIR}/ui/qt/utils/theme_styler.h"
    "${WIRESHARK_SOURCE_DIR}/ui/qt/utils/themes/color_math.cpp"
)
target_include_directories(packet_list_style_test PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}" "${WIRESHARK_SOURCE_DIR}")
target_link_libraries(packet_list_style_test PRIVATE Qt6::Widgets)
enable_testing()
add_test(NAME packet_list_style COMMAND packet_list_style_test)

add_executable(packet_comparison_test
    packet_comparison_test.cpp
    "${WIRESHARK_SOURCE_DIR}/ui/qt/utils/packet_comparison.cpp"
)
target_include_directories(packet_comparison_test PRIVATE "${WIRESHARK_SOURCE_DIR}")
target_link_libraries(packet_comparison_test PRIVATE Qt6::Core)
add_test(NAME packet_comparison COMMAND packet_comparison_test)
