#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vinbero_common/vinbero_common_Call.h>
#include <vinbero_common/vinbero_common_Config.h>
#include <vinbero_common/vinbero_common_Module.h>
#include <vinbero_common/vinbero_common_TlModule.h>
#include <vinbero_common/vinbero_common_ClModule.h>
#include <vinbero_common/vinbero_common_Status.h>
#include <vinbero_common/vinbero_common_Error.h>
#include <vinbero_common/vinbero_common_Log.h>
#include <libgenc/genc_cast.h>
#include <libgenc/genc_Tree.h>
#include <vinbero/vinbero_interface_MODULE.h>
#include <vinbero/vinbero_interface_CLOCAL.h>
#include <vinbero/vinbero_interface_CLSERVICE.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <gaio.h>
#include "vinbero_mt_epoll_tls_Version.h"

struct vinbero_mt_epoll_tls_Module {
    VINBERO_INTERFACE_CLOCAL_FUNCTION_POINTERS;
    VINBERO_INTERFACE_CLSERVICE_FUNCTION_POINTERS;
    SSL_CTX* sslContext;
    struct gaio_Methods ioMethods;
};

VINBERO_INTERFACE_MODULE_FUNCTIONS;
VINBERO_INTERFACE_CLOCAL_FUNCTIONS;
VINBERO_INTERFACE_CLSERVICE_FUNCTIONS;

struct vinbero_mt_epoll_tls_TlModule {
    int state;
};

struct vinbero_mt_epoll_tls_ClModule {
    SSL* ssl;
    struct gaio_Io clientIo;
};

static int vinbero_mt_epoll_tls_Ssl_read(struct gaio_Io* io, void* buffer, int readSize) {
    return SSL_read((SSL*)io->object.pointer, buffer, readSize);
}

static int vinbero_mt_epoll_tls_Ssl_write(struct gaio_Io* io, void* buffer, int writeSize) {
    return SSL_write((SSL*)io->object.pointer, buffer, writeSize);
}

static int vinbero_mt_epoll_tls_Ssl_sendfile(struct gaio_Io* outIo, struct gaio_Io* inIo, off_t* offset, int count) {
    fcntl(outIo->methods->fileno(outIo), F_SETFL, fcntl(outIo->methods->fileno(outIo), F_GETFL, 0) & ~O_NONBLOCK);
    char* buffer = malloc(count);
    inIo->methods->read(inIo, buffer, count);
    outIo->methods->write(outIo, buffer, count);
    free(buffer);
    fcntl(outIo->methods->fileno(outIo), F_SETFL, fcntl(outIo->methods->fileno(outIo), F_GETFL, 0) | O_NONBLOCK);
    return count;
}

static int vinbero_mt_epoll_tls_Ssl_fileno(struct gaio_Io* io) {
    SSL_get_fd((SSL*)io->object.pointer);
}

static int vinbero_mt_epoll_tls_Ssl_fstat(struct gaio_Io* io, struct stat* statBuffer) {
    return fstat(SSL_get_fd((SSL*)io->object.pointer), statBuffer);
}

static int vinbero_mt_epoll_tls_Ssl_close(struct gaio_Io* io) {
    SSL_shutdown((SSL*)io->object.pointer); 
    SSL_shutdown((SSL*)io->object.pointer);
    return close(SSL_get_fd((SSL*)io->object.pointer));
}

int vinbero_interface_MODULE_init(struct vinbero_common_Module* module) {
    VINBERO_COMMON_LOG_TRACE2();
    vinbero_common_Module_init(module, "vinbero_mt_epoll_tls", VINBERO_MT_EPOLL_TLS_VERSION, true);
    module->localModule.pointer = malloc(1 * sizeof(struct vinbero_mt_epoll_tls_Module));
    struct vinbero_mt_epoll_tls_Module* localModule = module->localModule.pointer;
    SSL_load_error_strings();    
    ERR_load_crypto_strings();
    OpenSSL_add_ssl_algorithms();


/*
    VINBERO_INTERFACE_BASIC_DLSYM(module, struct vinbero_mt_epoll_tls_Module);
    VINBERO_INTERFACE_CLOCAL_DLSYM(module, struct vinbero_mt_epoll_tls_Module);
    VINBERO_INTERFACE_CLSERVICE_DLSYM(module, struct vinbero_mt_epoll_tls_Module);
*/
    localModule->sslContext = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_ecdh_auto(localModule->sslContext, 1);
    char* certificateFile;
    char* privateKeyFile;

    vinbero_common_Config_getRequiredString(module->config, module, "vinbero_mt_epoll_tls.certificateFile", (const char**)&certificateFile);
    if((certificateFile = realpath(certificateFile, NULL)) == NULL) {
        VINBERO_COMMON_LOG_ERROR("Wrong certificate file path");
        return VINBERO_COMMON_ERROR_INVALID_CONFIG;
    }

    vinbero_common_Config_getRequiredString(module->config, module, "vinbero_mt_epoll_tls.privateKeyFile", (const char**)&privateKeyFile);
    if((privateKeyFile = realpath(privateKeyFile, NULL)) == NULL) {
        VINBERO_COMMON_LOG_ERROR("Wrong private key file path");
        return VINBERO_COMMON_ERROR_INVALID_CONFIG;
    }
 
    if(SSL_CTX_use_certificate_file(localModule->sslContext, certificateFile, SSL_FILETYPE_PEM) <= 0) {
        free(certificateFile);
        ERR_print_errors_fp(stderr);
        return VINBERO_COMMON_ERROR_UNKNOWN;
    }
    if(SSL_CTX_use_PrivateKey_file(localModule->sslContext, privateKeyFile, SSL_FILETYPE_PEM) <= 0) {
        free(privateKeyFile);
        ERR_print_errors_fp(stderr);
        return VINBERO_COMMON_ERROR_UNKNOWN;
    }

    free(certificateFile);
    free(privateKeyFile);

    localModule->ioMethods.read = vinbero_mt_epoll_tls_Ssl_read;
    localModule->ioMethods.write = vinbero_mt_epoll_tls_Ssl_write;
    localModule->ioMethods.sendfile = vinbero_mt_epoll_tls_Ssl_sendfile;
    localModule->ioMethods.fstat = vinbero_mt_epoll_tls_Ssl_fstat;
    localModule->ioMethods.fileno = vinbero_mt_epoll_tls_Ssl_fileno;
    localModule->ioMethods.close = vinbero_mt_epoll_tls_Ssl_close;

    return VINBERO_COMMON_STATUS_SUCCESS;
}

int vinbero_interface_TLOCAL_init(struct vinbero_common_TlModule* tlModule) {
    VINBERO_COMMON_LOG_TRACE2();
    tlModule->localTlModule.pointer = malloc(sizeof(struct vinbero_mt_epoll_tls_TlModule));
    struct vinbero_mt_epoll_tls_TlModule* localTlModule = tlModule->localTlModule.pointer;
    localTlModule->state = 0;
    return VINBERO_COMMON_STATUS_SUCCESS;
}

int vinbero_interface_CLOCAL_init(struct vinbero_common_ClModule* clModule) {
    VINBERO_COMMON_LOG_TRACE2();
    int ret;
    struct vinbero_common_Module* module = clModule->tlModule->module;
    clModule->localClModule.pointer = malloc(1 * sizeof(struct vinbero_mt_epoll_tls_ClModule));
    struct vinbero_mt_epoll_tls_ClModule* localClModule = clModule->localClModule.pointer;
    struct vinbero_mt_epoll_tls_Module* localModule = clModule->tlModule->module->localModule.pointer;
    struct gaio_Io* localClientIo = clModule->arg;
    localClModule->ssl = SSL_new(GENC_CAST(module->localModule.pointer, struct vinbero_mt_epoll_tls_Module*)->sslContext);
    if(SSL_set_fd(localClModule->ssl, dup(localClientIo->object.integer)) != 1) {
        VINBERO_COMMON_LOG_ERROR("SSL_set_fd() failed");
        return VINBERO_COMMON_ERROR_FO;
    }
    localClModule->clientIo.object.pointer = localClModule->ssl;
    localClModule->clientIo.methods = &(localModule->ioMethods);
    struct vinbero_common_Module* childModule = &GENC_TREE_NODE_GET_CHILD(clModule->tlModule->module, 0);
    struct vinbero_common_ClModule* childClModule = &GENC_TREE_NODE_GET_CHILD(clModule, 0);
    clModule->arg = &localClModule->clientIo;
//    childClModule->arg = &localClModule->clientIo;
/*
    VINBERO_COMMON_CALL(CLOCAL, init, childModule, &ret, childClModule);
    if(ret < VINBERO_COMMON_STATUS_SUCCESS)
        return ret;
    return VINBERO_COMMON_STATUS_SUCCESS;
*/
}

int vinbero_interface_CLSERVICE_call(struct vinbero_common_ClModule* clModule) {
    VINBERO_COMMON_LOG_TRACE2();
    int ret;
    struct vinbero_common_Module* childModule = &GENC_TREE_NODE_GET_CHILD(clModule->tlModule->module, 0);
    struct vinbero_mt_epoll_tls_Module* localModule = clModule->tlModule->module->localModule.pointer;
    struct vinbero_mt_epoll_tls_TlModule* tlModule = clModule->tlModule->localTlModule.pointer;
    struct vinbero_mt_epoll_tls_ClModule* localClModule = clModule->localClModule.pointer;
    struct vinbero_common_ClModule* childClModule = &GENC_TREE_NODE_GET_CHILD(clModule, 0);

    if(SSL_is_init_finished(localClModule->ssl)) {
        VINBERO_COMMON_CALL(CLSERVICE, call, childModule, &ret, childClModule);
        return ret;
    }

    int result;
    if((result = SSL_accept(localClModule->ssl)) != 1) {
        switch(SSL_get_error(localClModule->ssl, result)) {
            case SSL_ERROR_NONE:
                VINBERO_COMMON_LOG_ERROR("SSL_ERROR_NONE");
                break;
            case SSL_ERROR_WANT_WRITE:
                VINBERO_COMMON_LOG_DEBUG("SSL_ERROR_WANT_WRITE");
                return VINBERO_COMMON_STATUS_AGAIN;
            case SSL_ERROR_WANT_READ:
                VINBERO_COMMON_LOG_DEBUG("SSL_ERROR_WANT_READ");
                return VINBERO_COMMON_STATUS_AGAIN;
            case SSL_ERROR_ZERO_RETURN:
                VINBERO_COMMON_LOG_ERROR("SSL_ERROR_ZERO_RETURN");
                break;
            case SSL_ERROR_SYSCALL:
                VINBERO_COMMON_LOG_ERROR("SSL_ERROR_SYSCALL");
                break;
            case SSL_ERROR_WANT_CONNECT:
                VINBERO_COMMON_LOG_ERROR("SSL_ERROR_WANT_CONNET");
                break;
            case SSL_ERROR_WANT_ACCEPT:
                VINBERO_COMMON_LOG_ERROR("SSL_ERROR_WANT_ACCEPT");
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                VINBERO_COMMON_LOG_ERROR("SSL_ERROR_WANT_X509_LOOKUP");
                break;
            case SSL_ERROR_SSL:
                VINBERO_COMMON_LOG_ERROR("SSL_ERROR_SSL");
                break;
            default:
                VINBERO_COMMON_LOG_ERROR("SSL_ERROR_???");
                break;
        }
        VINBERO_COMMON_LOG_ERROR("SSL_accept() failed");
        return VINBERO_COMMON_ERROR_UNKNOWN;
    }
}

int vinbero_interface_TLOCAL_rInit(struct vinbero_common_TlModule* tlModule) {
    return VINBERO_COMMON_STATUS_SUCCESS;
}

int vinbero_interface_MODULE_rInit(struct vinbero_common_Module* module) {
    return VINBERO_COMMON_STATUS_SUCCESS;
}

int vinbero_interface_CLOCAL_destroy(struct vinbero_common_ClModule* clModule) {
    VINBERO_COMMON_LOG_TRACE2();
    struct vinbero_mt_epoll_tls_ClModule* localClModule = clModule->localClModule.pointer;
    localClModule->clientIo.methods->close(&localClModule->clientIo);
    SSL_free(localClModule->ssl);
}

int vinbero_interface_TLOCAL_destroy(struct vinbero_common_TlModule* tlModule) {
    VINBERO_COMMON_LOG_TRACE2();
    return VINBERO_COMMON_STATUS_SUCCESS;
}

int vinbero_interface_TLOCAL_rDestroy(struct vinbero_common_TlModule* tlModule) {
    VINBERO_COMMON_LOG_TRACE2();
    return VINBERO_COMMON_STATUS_SUCCESS;
}


int vinbero_interface_MODULE_destroy(struct vinbero_common_Module* module) {
    return VINBERO_COMMON_STATUS_SUCCESS;
}

int vinbero_interface_MODULE_rDestroy(struct vinbero_common_Module* module) {
    VINBERO_COMMON_LOG_TRACE2();
    struct vinbero_mt_epoll_tls_Module* localModule = module->localModule.pointer;
    free(module->localModule.pointer);
    free(module);
    EVP_cleanup();
    return VINBERO_COMMON_STATUS_SUCCESS;
}
