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
#include <openssl/ssl.h>
#include <openssl/err.h>

struct tucube_epoll_tls_Module {
    TUCUBE_IBASE_FUNCTION_POINTERS;
    TUCUBE_ICLOCAL_FUNCTION_POINTERS;
    TUCUBE_ICLSERVICE_FUNCTION_POINTERS;
    SSL_CTX* sslContext;
};

TUCUBE_IBASE_FUNCTIONS;
TUCUBE_ICLOCAL_FUNCTIONS;
TUCUBE_ICLSERVICE_FUNCTIONS;

struct tucube_epoll_tls_ClData {
    SSL* ssl;
};

int tucube_IBase_init(struct tucube_Module_Config* moduleConfig, struct tucube_Module_List* moduleList, void* args[]) {
#define TUCUBE_LOCAL_MODULE GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)
    SSL_load_error_strings();	
    ERR_load_crypto_strings();
    OpenSSL_add_ssl_algorithms();


    if(GON_C_LIST_ELEMENT_NEXT(moduleConfig) == NULL)
        errx(EXIT_FAILURE, "tucube_epoll_tls requires another module");

    struct tucube_Module* module = malloc(1 * sizeof(struct tucube_Module));
    GON_C_LIST_ELEMENT_INIT(module);
    module->pointer = malloc(1 * sizeof(struct tucube_epoll_tls_Module));

    TUCUBE_MODULE_DLOPEN(module, moduleConfig);
    TUCUBE_IBASE_DLSYM(module, struct tucube_epoll_tls_Module);
    TUCUBE_ICLOCAL_DLSYM(module, struct tucube_epoll_tls_Module);
    TUCUBE_ICLSERVICE_DLSYM(module, struct tucube_epoll_tls_Module);

    TUCUBE_LOCAL_MODULE->sslContext = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_ecdh_auto(TUCUBE_LOCAL_MODULE->sslContext, 1);
    if(SSL_CTX_use_certificate_file(TUCUBE_LOCAL_MODULE->sslContext, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if(SSL_CTX_use_PrivateKey_file(TUCUBE_LOCAL_MODULE->sslContext, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }


    GON_C_LIST_APPEND(moduleList, module);

    if(TUCUBE_LOCAL_MODULE->tucube_IBase_init(GON_C_LIST_ELEMENT_NEXT(moduleConfig), moduleList, NULL) == -1)
        errx(EXIT_FAILURE, "%s: %u: tucube_IBase_init() failed", __FILE__, __LINE__);

    return 0;
#undef TUCUBE_LOCAL_MODULE
}

int tucube_IBase_tlInit(struct tucube_Module* module, struct tucube_Module_Config* moduleConfig, void* args[]) {
#define TUCUBE_LOCAL_MODULE GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)
    return TUCUBE_LOCAL_MODULE->tucube_IBase_tlInit(GON_C_LIST_ELEMENT_NEXT(module), GON_C_LIST_ELEMENT_NEXT(moduleConfig), NULL);
#undef TUCUBE_LOCAL_MODULE
}

int tucube_ICLocal_init(struct tucube_Module* module, struct tucube_ClData_List* clDataList, void* args[]) {
#define TUCUBE_LOCAL_MODULE GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)
#define TUCUBE_LOCAL_CLIENT_SOCKET ((int*)args[0])
#define TUCUBE_LOCAL_CLDATA GON_C_CAST(clData->pointer, struct tucube_epoll_tls_ClData*)
    struct tucube_ClData* clData = malloc(1 * sizeof(struct tucube_ClData));
    clData->pointer = malloc(1 * sizeof(struct tucube_epoll_tls_ClData));
    TUCUBE_LOCAL_CLDATA->ssl = SSL_new(GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)->sslContext);
    if(SSL_set_fd(TUCUBE_LOCAL_CLDATA->ssl, *TUCUBE_LOCAL_CLIENT_SOCKET) != 1) {
        warnx("%s: %u: SSL_set_fd() failed", __FILE__, __LINE__);
	return -1;
    }
//    SSL_set_accept_state(TUCUBE_LOCAL_CLDATA->ssl);
//    if((result = SSL_do_handshake(TUCUBE_LOCAL_CLDATA->ssl)) != 1) {
    int result;
    fcntl(*TUCUBE_LOCAL_CLIENT_SOCKET, F_SETFL, fcntl(*TUCUBE_LOCAL_CLIENT_SOCKET, F_GETFL, 0) & ~O_NONBLOCK);

    if((result = SSL_accept(TUCUBE_LOCAL_CLDATA->ssl)) != 1) {
        warnx("while loop");
        switch(SSL_get_error(TUCUBE_LOCAL_CLDATA->ssl, result)) {
            case SSL_ERROR_NONE:
	        warnx("%s: %u: SSL_ERROR_NONE", __FILE__, __LINE__);
		break;
	    case SSL_ERROR_WANT_WRITE:
	        warnx("%s: %u: SSL_ERROR_WANT_WRITE", __FILE__, __LINE__);
		break;
	    case SSL_ERROR_WANT_READ:
	        warnx("%s: %u: SSL_ERROR_WANT_READ", __FILE__, __LINE__);
		break;
	    case SSL_ERROR_ZERO_RETURN:
	        warnx("%s: %u: SSL_ERROR_ZERO_RETURN", __FILE__, __LINE__);
		break;
	    case SSL_ERROR_SYSCALL:
	        warnx("%s: %u: SSL_ERROR_SYSCALL", __FILE__, __LINE__);
		break;
            case SSL_ERROR_WANT_CONNECT:
		warnx("%s: %u: SSL_ERROR_WANT_CONNET", __FILE__, __LINE__);
		break;
	    case SSL_ERROR_WANT_ACCEPT:
		warnx("%s: %u: SSL_ERROR_WANT_ACCEPT", __FILE__, __LINE__);
		break;
	    case SSL_ERROR_WANT_X509_LOOKUP:
		warnx("%s: %u: SSL_ERROR_WANT_X509_LOOKUP", __FILE__, __LINE__);
		break;
	    case SSL_ERROR_SSL:
		warnx("%s: %u: SSL_ERROR_SSL", __FILE__, __LINE__);
		break;
	    default:
	        warnx("SSL_ERROR_???");
		break;
        }
        return -1;
    }
    fcntl(*TUCUBE_LOCAL_CLIENT_SOCKET, F_SETFL, fcntl(*TUCUBE_LOCAL_CLIENT_SOCKET, F_GETFL, 0) | O_NONBLOCK);


    warnx("accept success!!");
return -1;
    GON_C_LIST_APPEND(clDataList, clData);
    return TUCUBE_LOCAL_MODULE->tucube_ICLocal_init(GON_C_LIST_ELEMENT_NEXT(module), clDataList, args);
#undef TUCUBE_LOCAL_CLDATA
#undef TUCUBE_LOCAL_CLIENT_SOCKET
#undef TUCUBE_LOCAL_MODULE
}


int tucube_IClService_call(struct tucube_Module* module, struct tucube_ClData* clData, void* args[]) {
#define TUCUBE_LOCAL_MODULE GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)
#define TUCUBE_LOCAL_CLDATA GON_C_CAST(clData->pointer, struct tucube_epoll_tls_ClData*)
    return TUCUBE_LOCAL_MODULE->tucube_IClService_call(GON_C_LIST_ELEMENT_NEXT(module), clData, (void*[]){TUCUBE_LOCAL_CLDATA->ssl, SSL_read, SSL_write});
#undef TUCUBE_LOCAL_CLDATA
#undef TUCUBE_LOCAL_MODULE
}

int tucube_ICLocal_destroy(struct tucube_Module* module, struct tucube_ClData* clData) {
#define TUCUBE_LOCAL_MODULE GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)
#define TUCUBE_LOCAL_CLDATA GON_C_CAST(clData->pointer, struct tucube_epoll_tls_ClData*)
    SSL_free(TUCUBE_LOCAL_CLDATA->ssl);
    return TUCUBE_LOCAL_MODULE->tucube_ICLocal_destroy(GON_C_LIST_ELEMENT_NEXT(module), clData);
#undef TUCUBE_LOCAL_CLDATA
#undef TUCUBE_LOCAL_MODULE
}

int tucube_IBase_tlDestroy(struct tucube_Module* module) {
#define TUCUBE_LOCAL_MODULE GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)
    return TUCUBE_LOCAL_MODULE->tucube_IBase_tlDestroy(GON_C_LIST_ELEMENT_NEXT(module));
#undef TUCUBE_LOCAL_MODULE
}

int tucube_IBase_destroy(struct tucube_Module* module) {
#define TUCUBE_LOCAL_MODULE GON_C_CAST(module->pointer, struct tucube_epoll_tls_Module*)
    TUCUBE_LOCAL_MODULE->tucube_IBase_destroy(GON_C_LIST_ELEMENT_NEXT(module));
//    dlclose(module->dl_handle);
    free(module->pointer);
    free(module);
    EVP_cleanup();
    return 0;
#undef TUCUBE_LOCAL_MODULE
}
