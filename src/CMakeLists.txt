cmake_minimum_required(VERSION 3.8)
project(tucube_epoll_tls)
set(CMAKE_BUILD_TYPE Debug)
add_library(tucube_epoll_tls MODULE tucube_epoll_tls.c)
set_target_properties(tucube_epoll_tls PROPERTIES PREFIX "")
target_link_libraries(tucube_epoll_tls ssl)
target_link_libraries(tucube_epoll_tls crypto)
install(TARGETS tucube_epoll_tls
        LIBRARY DESTINATION lib/tucube)
