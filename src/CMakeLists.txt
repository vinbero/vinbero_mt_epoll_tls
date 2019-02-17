find_package(fastdl REQUIRED)
find_package(gaio REQUIRED)
find_package(vinbero_com REQUIRED)

add_library(vinbero_mt_epoll_tls MODULE)

target_sources(
    vinbero_mt_epoll_tls
    PRIVATE
    vinbero_mt_epoll_tls.c
)

target_compile_options(
    vinbero_mt_epoll_tls
    PRIVATE
    -Wall
)

set_target_properties(
    vinbero_mt_epoll_tls
    PROPERTIES
    C_STANDARD 11
    PREFIX ""
    PUBLIC_HEADER ""
    VERSION ${version}
    SOVERSION ${soversion}
)

target_include_directories(
    vinbero_mt_epoll_tls
    PRIVATE
    ${PROJECT_BINARY_DIR}
)

target_link_libraries(
    vinbero_mt_epoll_tls
    vinbero_com::vinbero_com
    fastdl::fastdl
    gaio::gaio
    crypto
    ssl
)

configure_file(
    "${PROJECT_SOURCE_DIR}/src/config.h.in"
    "${PROJECT_BINARY_DIR}/config.h"
    @ONLY
)

install(
    TARGETS vinbero_mt_epoll_tls
    LIBRARY DESTINATION lib/vinbero
    PUBLIC_HEADER DESTINATION include/vinbero
)
