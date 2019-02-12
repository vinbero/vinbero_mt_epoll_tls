add_library(vinbero_mt_epoll_tls MODULE vinbero_mt_epoll_tls.c)
set_target_properties(vinbero_mt_epoll_tls
                      PROPERTIES PREFIX ""
                                 PUBLIC_HEADER ""
                                 VERSION ${version}
                                 SOVERSION ${soversion})

find_library(fastdl libfastdl.so REQUIRED)
find_library(gaio libgaio.so.0.3 REQUIRED)
find_library(vinbero_com libvinbero_com.so REQUIRED)

target_link_libraries(vinbero_mt_epoll_tls
                      ${vinbero_com}
                      ${fastdl}
                      ${gaio}
                      crypto
                      ssl)

install(TARGETS vinbero_mt_epoll_tls
        LIBRARY DESTINATION lib/vinbero
        PUBLIC_HEADER DESTINATION include/vinbero)
