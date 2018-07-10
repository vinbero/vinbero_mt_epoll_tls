add_library(vinbero_mt_epoll_tls MODULE vinbero_mt_epoll_tls.c)
set_target_properties(vinbero_mt_epoll_tls
                      PROPERTIES PREFIX ""
                                 PUBLIC_HEADER ""
                                 VERSION ${vinbero_mt_epoll_tls_version}
                                 SOVERSION ${vinbero_mt_epoll_tls_soversion})

find_library(fastdl libfastdl.so REQUIRED)
find_library(gaio libgaio.so.0.3 REQUIRED)
find_library(vinbero_common libvinbero_common.so REQUIRED)

target_link_libraries(vinbero_mt_epoll_tls
                      ${vinbero_common}
                      ${fastdl}
                      ${gaio}
                      crypto
                      ssl)

install(TARGETS vinbero_mt_epoll_tls
        LIBRARY DESTINATION lib/vinbero
        PUBLIC_HEADER DESTINATION include/vinbero)
