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
#include <libgenc/genc_cast.h>
#include <libgenc/genc_list.h>
#include <libgenc/genc_ltostr.h>
#include <tucube/tucube_IBase.h>
#include <tucube/tucube_ICLocal.h>
#include <tucube/tucube_IClService.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <gaio.h>

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
#define TUCUBE_LOCAL_MODULE GENC_CAST(module->generic.pointer, struct tucube_epoll_tls_Module*)
    warnx("%s: %u: %s", __FILE__, __LINE__, __FUNCTION__);
    SSL_load_error_strings();	
    ERR_load_crypto_strings();
    OpenSSL_add_ssl_algorithms();


    if(GENC_LIST_ELEMENT_NEXT(moduleConfig) == NULL)
        errx(EXIT_FAILURE, "tucube_epoll_tls requires another module");

    struct tucube_Module* module = malloc(1 * sizeof(struct tucube_Module));
    GENC_LIST_ELEMENT_INIT(module);
    module->generic.pointer = malloc(1 * sizeof(struct tucube_epoll_tls_Module));

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


    GENC_LIST_APPEND(moduleList, module);

    if(TUCUBE_LOCAL_MODULE->tucube_IBase_init(GENC_LIST_ELEMENT_NEXT(moduleConfig), moduleList, (void*[]){NULL}) == -1)
        errx(EXIT_FAILURE, "%s: %u: tucube_IBase_init() failed", __FILE__, __LINE__);

    return 0;
#undef TUCUBE_LOCAL_MODULE
}

int tucube_IBase_tlInit(struct tucube_Module* module, struct tucube_Module_Config* moduleConfig, void* args[]) {
#define TUCUBE_LOCAL_MODULE GENC_CAST(module->generic.pointer, struct tucube_epoll_tls_Module*)
    warnx("%s: %u: %s", __FILE__, __LINE__, __FUNCTION__);
    return TUCUBE_LOCAL_MODULE->tucube_IBase_tlInit(GENC_LIST_ELEMENT_NEXT(module), GENC_LIST_ELEMENT_NEXT(moduleConfig), (void*[]){NULL});
#undef TUCUBE_LOCAL_MODULE
}

static int tucube_epoll_tls_Ssl_read(struct gaio_Io* io, void* buffer, int readSize) {
    return SSL_read((SSL*)io->object.pointer, buffer, readSize);
}

static int tucube_epoll_tls_Ssl_write(struct gaio_Io* io, void* buffer, int writeSize) {
    return SSL_write((SSL*)io->object.pointer, buffer, writeSize);
}

static int tucube_epoll_tls_Ssl_fcntl(struct gaio_Io* io, int command, int argCount, ...) {
    va_list args;
    va_start(args, argCount);
    int returnValue = fcntl(SSL_get_fd((SSL*)io->object.pointer), command, argCount, args);
    va_end(args);
    return returnValue;
}

int tucube_ICLocal_init(struct tucube_Module* module, struct tucube_ClData_List* clDataList, void* args[]) {
#define TUCUBE_LOCAL_MODULE GENC_CAST(module->generic.pointer, struct tucube_epoll_tls_Module*)
#define TUCUBE_LOCAL_FD_POINTER_CLIENT_IO ((struct gaio_Io*)args[0])
#define TUCUBE_LOCAL_CLDATA GENC_CAST(clData->generic.pointer, struct tucube_epoll_tls_ClData*)
    warnx("%s: %u: %s", __FILE__, __LINE__, __FUNCTION__);
    struct tucube_ClData* clData = malloc(1 * sizeof(struct tucube_ClData));
    GENC_LIST_ELEMENT_INIT(clData);
    clData->generic.pointer = malloc(1 * sizeof(struct tucube_epoll_tls_ClData));
    TUCUBE_LOCAL_CLDATA->ssl = SSL_new(GENC_CAST(module->generic.pointer, struct tucube_epoll_tls_Module*)->sslContext);
    if(SSL_set_fd(TUCUBE_LOCAL_CLDATA->ssl, *(int*)TUCUBE_LOCAL_FD_POINTER_CLIENT_IO->object.pointer) != 1) {
        warnx("%s: %u: SSL_set_fd() failed", __FILE__, __LINE__);
	return -1;
    }

//    SSL_set_accept_state(TUCUBE_LOCAL_CLDATA->ssl);
//    if((result = SSL_do_handshake(TUCUBE_LOCAL_CLDATA->ssl)) != 1) {
    int result;
    TUCUBE_LOCAL_FD_POINTER_CLIENT_IO->fcntl(TUCUBE_LOCAL_FD_POINTER_CLIENT_IO, F_SETFL, TUCUBE_LOCAL_FD_POINTER_CLIENT_IO->fcntl(TUCUBE_LOCAL_FD_POINTER_CLIENT_IO, F_GETFL, 0) & ~O_NONBLOCK);

    if((result = SSL_accept(TUCUBE_LOCAL_CLDATA->ssl)) != 1) {
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
    TUCUBE_LOCAL_FD_POINTER_CLIENT_IO->fcntl(TUCUBE_LOCAL_FD_POINTER_CLIENT_IO, F_SETFL, TUCUBE_LOCAL_FD_POINTER_CLIENT_IO->fcntl(TUCUBE_LOCAL_FD_POINTER_CLIENT_IO, F_GETFL, 0) | O_NONBLOCK);


    GENC_LIST_APPEND(clDataList, clData);
    struct gaio_Io* io = malloc(sizeof(struct gaio_Io*));
    io->object.pointer = TUCUBE_LOCAL_CLDATA->ssl;
    io->read = tucube_epoll_tls_Ssl_read;
    io->write = tucube_epoll_tls_Ssl_write;
    io->fcntl = tucube_epoll_tls_Ssl_fcntl;
    //io->sendfile =
    io->close = gaio_Nop_close;
    return TUCUBE_LOCAL_MODULE->tucube_ICLocal_init(GENC_LIST_ELEMENT_NEXT(module), clDataList, (void*[]){io, NULL});
#undef TUCUBE_LOCAL_CLDATA
#undef TUCUBE_LOCAL_FD_POINTER_CLIENT_IO
#undef TUCUBE_LOCAL_MODULE
}



int tucube_IClService_call(struct tucube_Module* module, struct tucube_ClData* clData, void* args[]) {
#define TUCUBE_LOCAL_MODULE GENC_CAST(module->generic.pointer, struct tucube_epoll_tls_Module*)
#define TUCUBE_LOCAL_CLDATA GENC_CAST(clData->generic.pointer, struct tucube_epoll_tls_ClData*)
    warnx("%s: %u: %s", __FILE__, __LINE__, __FUNCTION__);
    return TUCUBE_LOCAL_MODULE->tucube_IClService_call(GENC_LIST_ELEMENT_NEXT(module), GENC_LIST_ELEMENT_NEXT(clData), (void*[]){NULL});
#undef TUCUBE_LOCAL_CLDATA
#undef TUCUBE_LOCAL_MODULE
}

int tucube_ICLocal_destroy(struct tucube_Module* module, struct tucube_ClData* clData) {
#define TUCUBE_LOCAL_MODULE GENC_CAST(module->generic.pointer, struct tucube_epoll_tls_Module*)
#define TUCUBE_LOCAL_CLDATA GENC_CAST(clData->generic.pointer, struct tucube_epoll_tls_ClData*)
    warnx("%s: %u: %s", __FILE__, __LINE__, __FUNCTION__);
    return TUCUBE_LOCAL_MODULE->tucube_ICLocal_destroy(GENC_LIST_ELEMENT_NEXT(module), GENC_LIST_ELEMENT_NEXT(clData));

    SSL_free(TUCUBE_LOCAL_CLDATA->ssl);

#undef TUCUBE_LOCAL_CLDATA
#undef TUCUBE_LOCAL_MODULE
}

int tucube_IBase_tlDestroy(struct tucube_Module* module) {
#define TUCUBE_LOCAL_MODULE GENC_CAST(module->generic.pointer, struct tucube_epoll_tls_Module*)
    warnx("%s: %u: %s", __FILE__, __LINE__, __FUNCTION__);
    return TUCUBE_LOCAL_MODULE->tucube_IBase_tlDestroy(GENC_LIST_ELEMENT_NEXT(module));
#undef TUCUBE_LOCAL_MODULE
}

int tucube_IBase_destroy(struct tucube_Module* module) {
#define TUCUBE_LOCAL_MODULE GENC_CAST(module->generic.pointer, struct tucube_epoll_tls_Module*)
    warnx("%s: %u: %s", __FILE__, __LINE__, __FUNCTION__);
    TUCUBE_LOCAL_MODULE->tucube_IBase_destroy(GENC_LIST_ELEMENT_NEXT(module));
//    dlclose(module->dl_handle);
    free(module->generic.pointer);
    free(module);
    EVP_cleanup();
    return 0;
#undef TUCUBE_LOCAL_MODULE
}
