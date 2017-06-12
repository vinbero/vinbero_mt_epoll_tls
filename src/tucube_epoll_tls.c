#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <unistd.h>
#include <gon_http_parser.h>
#include <tucube/tucube_Module.h>
#include <tucube/tucube_ClData.h>
#include <libgon_c/gon_c_cast.h>
#include <libgon_c/gon_c_list.h>
#include <libgon_c/gon_c_ltostr.h>
#include <tucube/tucube_IBase.h>
#include <tucube/tucube_ICLocal.h>
#include <tucube/tucube_IClService.h>

struct tucube_epoll_tls_Module {
    TUCUBE_IBASE_FUNCTION_POINTERS;
    TUCUBE_ICLOCAL_FUNCTION_POINTERS;
    TUCUBE_ICLSERVICE_FUNCTION_POINTERS;
};

TUCUBE_IBASE_FUNCTIONS;
TUCUBE_ICLOCAL_FUNCTIONS;
TUCUBE_ICLSERVICE_FUNCTIONS;

int tucube_IBase_init(struct tucube_Module_Config* moduleConfig, struct tucube_Module_List* moduleList, void* args[]) {
#define TUCUBE_LOCAL_MODULE GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)
    if(GON_C_LIST_ELEMENT_NEXT(moduleConfig) == NULL)
        errx(EXIT_FAILURE, "tucube_epoll_tls requires another module");

    struct tucube_Module* module = malloc(1 * sizeof(struct tucube_Module));
    GON_C_LIST_ELEMENT_INIT(module);
    module->pointer = malloc(1 * sizeof(struct tucube_epoll_tls_Module));

    TUCUBE_MODULE_DLOPEN(module, moduleConfig);
    TUCUBE_IBASE_DLSYM(module, struct tucube_epoll_tls_Module);
    TUCUBE_ICLOCAL_DLSYM(module, struct tucube_epoll_tls_Module);
    TUCUBE_ICLSERVICE_DLSYM(module, struct tucube_epoll_tls_Module);

    GON_C_LIST_APPEND(moduleList, module);

    if(TUCUBE_LOCAL_MODULE->tucube_IBase_init(GON_C_LIST_ELEMENT_NEXT(moduleConfig), moduleList, NULL) == -1)
        errx(EXIT_FAILURE, "%s: %u: tucube_IBase_init() failed", __FILE__, __LINE__);

    return 0;
#undef TUCUBE_LOCAL_MODULE
}

int tucube_IBase_tlInit(struct tucube_Module* module, struct tucube_Module_Config* moduleConfig, void* args[]) {
#define TUCUBE_LOCAL_MODULE GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)
    TUCUBE_LOCAL_MODULE->tucube_IBase_tlInit(GON_C_LIST_ELEMENT_NEXT(module), GON_C_LIST_ELEMENT_NEXT(moduleConfig), NULL);
    return 0;
#undef TUCUBE_LOCAL_MODULE
}

int tucube_ICLocal_init(struct tucube_Module* module, struct tucube_ClData_List* clDataList, void* args[]) {
#define TUCUBE_LOCAL_MODULE GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)
    return TUCUBE_LOCAL_MODULE->tucube_ICLocal_init(GON_C_LIST_ELEMENT_NEXT(module), clDataList, args);
#undef TUCUBE_LOCAL_MODULE
}


int tucube_IClService_call(struct tucube_Module* module, struct tucube_ClData* clData, void* args[]) {
#define TUCUBE_LOCAL_MODULE GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)
    return TUCUBE_LOCAL_MODULE->tucube_IClService_call(GON_C_LIST_ELEMENT_NEXT(module), clData, args);
#undef TUCUBE_LOCAL_MODULE
}

int tucube_ICLocal_destroy(struct tucube_Module* module, struct tucube_ClData* clData) {
#define TUCUBE_LOCAL_MODULE GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)
    return TUCUBE_LOCAL_MODULE->tucube_ICLocal_destroy(GON_C_LIST_ELEMENT_NEXT(module), clData);
#undef TUCUBE_LOCAL_MODULE
}

int tucube_IBase_tlDestroy(struct tucube_Module* module) {
#define TUCUBE_LOCAL_MODULE GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)
    TUCUBE_LOCAL_MODULE->tucube_IBase_tlDestroy(GON_C_LIST_ELEMENT_NEXT(module));
    return 0;
#undef TUCUBE_LOCAL_MODULE
}

int tucube_IBase_destroy(struct tucube_Module* module) {
#define TUCUBE_LOCAL_MODULE GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)
    TUCUBE_LOCAL_MODULE->tucube_IBase_destroy(GON_C_LIST_ELEMENT_NEXT(module));
//    dlclose(module->dl_handle);
    free(module->pointer);
    free(module);
    return 0;
#undef TUCUBE_LOCAL_MODULE
}
