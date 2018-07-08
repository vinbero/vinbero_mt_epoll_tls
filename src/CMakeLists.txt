cmake_minimum_required(VERSION 3.8)
project(vinbero_mt_epoll_tls)
set(CMAKE_BUILD_TYPE Debug)
add_library(vinbero_mt_epoll_tls MODULE vinbero_mt_epoll_tls.c)
set_target_properties(vinbero_mt_epoll_tls PROPERTIES PREFIX "")
target_link_libraries(vinbero_mt_epoll_tls ssl)
target_link_libraries(vinbero_mt_epoll_tls crypto)
install(TARGETS vinbero_mt_epoll_tls
        LIBRARY DESTINATION lib/vinbero)
