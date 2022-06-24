project(syscall_list LANGUAGES CXX)

add_executable(syscall_list
               src/main.cpp)
set_property(TARGET syscall_list PROPERTY CXX_STANDARD 20)

target_include_directories(syscall_list PRIVATE ${DYNINST_INCLUDE_DIR} ${DYNINST_Boost_INCLUDE_DIRS} ${DYNINST_TBB_INCLUDE_DIRS})
target_compile_definitions(syscall_list PRIVATE ${DYNINST_Boost_DEFINITIONS})

target_link_directories(syscall_list PRIVATE ${DYNINST_Boost_LIBRARY_DIRS})
target_link_libraries(syscall_list
                      dyninstAPI
                      instructionAPI
                      parseAPI
                      symtabAPI
                      common
                      absl::flags
                      absl::flags_parse
                      absl::flags_usage
                      ${DYNINST_Boost_LIBRARIES}
                      spdlog::spdlog
                      )

target_compile_options(syscall_list PRIVATE -Wextra -Wall -Werror -Wno-unused-parameter) #-Wno-maybe-uninitialized -O1)
