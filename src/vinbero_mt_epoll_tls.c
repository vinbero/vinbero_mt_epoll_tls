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
#include <vinbero_com/vinbero_com_Call.h>
#include <vinbero_com/vinbero_com_Config.h>
#include <vinbero_com/vinbero_com_Module.h>
#include <vinbero_com/vinbero_com_TlModule.h>
#include <vinbero_com/vinbero_com_ClModule.h>
#include <vinbero_com/vinbero_com_Status.h>
#include <vinbero_com/vinbero_com_Error.h>
#include <vinbero_com/vinbero_com_Log.h>
#include <libgenc/genc_Cast.h>
#include <libgenc/genc_Tree.h>
#include <vinbero/vinbero_iface_MODULE.h>
#include <vinbero/vinbero_iface_TLOCAL.h>
#include <vinbero/vinbero_iface_CLOCAL.h>
#include <vinbero/vinbero_iface_CLSERVICE.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <gaio.h>
#include "vinbero_mt_epoll_tls_Version.h"

VINBERO_COM_MODULE_META_NAME("vinbero_mt_epoll_tls")
VINBERO_COM_MODULE_META_LICENSE("MPL-2.0")
VINBERO_COM_MODULE_META_VERSION(
    VINBERO_MT_EPOLL_TLS_VERSION_MAJOR,
    VINBERO_MT_EPOLL_TLS_VERSION_MINOR,
    VINBERO_MT_EPOLL_TLS_VERSION_PATCH
)
VINBERO_COM_MODULE_META_IN_IFACES("TLOCAL,CLOCAL,CLSERVICE")
VINBERO_COM_MODULE_META_OUT_IFACES("TLOCAL,CLOCAL,CLSERVICE")
VINBERO_COM_MODULE_META_CHILD_COUNT(1, 1)

VINBERO_IFACE_MODULE_FUNCS;
VINBERO_IFACE_TLOCAL_FUNCS;
VINBERO_IFACE_CLOCAL_FUNCS;
VINBERO_IFACE_CLSERVICE_FUNCS;

struct vinbero_mt_epoll_tls_Module {
    VINBERO_IFACE_CLOCAL_FUNC_POINTERS;
    VINBERO_IFACE_CLSERVICE_FUNC_POINTERS;
    SSL_CTX* sslContext;
    struct gaio_Methods ioMethods;
};

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
    return SSL_get_fd((SSL*)io->object.pointer);
}

static int vinbero_mt_epoll_tls_Ssl_fstat(struct gaio_Io* io, struct stat* statBuffer) {
    return fstat(SSL_get_fd((SSL*)io->object.pointer), statBuffer);
}

static int vinbero_mt_epoll_tls_Ssl_close(struct gaio_Io* io) {
    SSL_shutdown((SSL*)io->object.pointer); 
    SSL_shutdown((SSL*)io->object.pointer);
    return close(SSL_get_fd((SSL*)io->object.pointer));
}

int vinbero_iface_MODULE_init(struct vinbero_com_Module* module) {
    VINBERO_COM_LOG_TRACE2();
    module->localModule.pointer = malloc(1 * sizeof(struct vinbero_mt_epoll_tls_Module));
    struct vinbero_mt_epoll_tls_Module* localModule = module->localModule.pointer;
    SSL_load_error_strings();    
    ERR_load_crypto_strings();
    OpenSSL_add_ssl_algorithms();

    localModule->sslContext = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_ecdh_auto(localModule->sslContext, 1);
    char* certificateFile;
    char* privateKeyFile;

    if(vinbero_com_Config_getRequiredConstring(module->config, module, "vinbero_mt_epoll_tls.certificateFile", (const char**)&certificateFile) == false)
        return VINBERO_COM_ERROR_INVALID_CONFIG;
    if((certificateFile = realpath(certificateFile, NULL)) == NULL) {
        VINBERO_COM_LOG_ERROR("Wrong certificate file path");
        return VINBERO_COM_ERROR_INVALID_CONFIG;
    }

    if(vinbero_com_Config_getRequiredConstring(module->config, module, "vinbero_mt_epoll_tls.privateKeyFile", (const char**)&privateKeyFile) == false)
        return VINBERO_COM_ERROR_INVALID_CONFIG;
    if((privateKeyFile = realpath(privateKeyFile, NULL)) == NULL) {
        VINBERO_COM_LOG_ERROR("Wrong private key file path");
        return VINBERO_COM_ERROR_INVALID_CONFIG;
    }
 
    if(SSL_CTX_use_certificate_file(localModule->sslContext, certificateFile, SSL_FILETYPE_PEM) <= 0) {
        free(certificateFile);
        ERR_print_errors_fp(stderr);
        return VINBERO_COM_ERROR_UNKNOWN;
    }
    if(SSL_CTX_use_PrivateKey_file(localModule->sslContext, privateKeyFile, SSL_FILETYPE_PEM) <= 0) {
        free(privateKeyFile);
        ERR_print_errors_fp(stderr);
        return VINBERO_COM_ERROR_UNKNOWN;
    }

    free(certificateFile);
    free(privateKeyFile);

    localModule->ioMethods.read = vinbero_mt_epoll_tls_Ssl_read;
    localModule->ioMethods.write = vinbero_mt_epoll_tls_Ssl_write;
    localModule->ioMethods.sendfile = vinbero_mt_epoll_tls_Ssl_sendfile;
    localModule->ioMethods.fstat = vinbero_mt_epoll_tls_Ssl_fstat;
    localModule->ioMethods.fileno = vinbero_mt_epoll_tls_Ssl_fileno;
    localModule->ioMethods.close = vinbero_mt_epoll_tls_Ssl_close;

    return VINBERO_COM_STATUS_SUCCESS;
}

int vinbero_iface_TLOCAL_init(struct vinbero_com_TlModule* tlModule) {
    VINBERO_COM_LOG_TRACE2();
    tlModule->localTlModule.pointer = malloc(sizeof(struct vinbero_mt_epoll_tls_TlModule));
    struct vinbero_mt_epoll_tls_TlModule* localTlModule = tlModule->localTlModule.pointer;
    localTlModule->state = 0;
    return VINBERO_COM_STATUS_SUCCESS;
}

int vinbero_iface_CLOCAL_init(struct vinbero_com_ClModule* clModule) {
    VINBERO_COM_LOG_TRACE2();
    struct vinbero_com_Module* module = clModule->tlModule->module;
    clModule->localClModule.pointer = malloc(1 * sizeof(struct vinbero_mt_epoll_tls_ClModule));
    struct vinbero_mt_epoll_tls_ClModule* localClModule = clModule->localClModule.pointer;
    struct vinbero_mt_epoll_tls_Module* localModule = clModule->tlModule->module->localModule.pointer;
    struct gaio_Io* localClientIo = clModule->arg;
    localClModule->ssl = SSL_new(GENC_CAST(module->localModule.pointer, struct vinbero_mt_epoll_tls_Module*)->sslContext);
    if(SSL_set_fd(localClModule->ssl, dup(localClientIo->object.integer)) != 1) {
        VINBERO_COM_LOG_ERROR("SSL_set_fd() failed");
        return VINBERO_COM_ERROR_FO;
    }
    localClModule->clientIo.object.pointer = localClModule->ssl;
    localClModule->clientIo.methods = &(localModule->ioMethods);
    clModule->arg = &localClModule->clientIo;
    return VINBERO_COM_STATUS_SUCCESS;
}

int vinbero_iface_CLSERVICE_call(struct vinbero_com_ClModule* clModule) {
    VINBERO_COM_LOG_TRACE2();
    int ret;
    struct vinbero_com_Module* childModule = GENC_TREE_NODE_RAW_GET(clModule->tlModule->module, 0);
    struct vinbero_mt_epoll_tls_ClModule* localClModule = clModule->localClModule.pointer;
    struct vinbero_com_ClModule* childClModule = GENC_TREE_NODE_RAW_GET(clModule, 0);

    if(SSL_is_init_finished(localClModule->ssl)) {
        VINBERO_COM_CALL(CLSERVICE, call, childModule, &ret, childClModule);
        return ret;
    }

    int result;
    if((result = SSL_accept(localClModule->ssl)) != 1) {
        switch(SSL_get_error(localClModule->ssl, result)) {
            case SSL_ERROR_NONE:
                VINBERO_COM_LOG_ERROR("SSL_ERROR_NONE");
                break;
            case SSL_ERROR_WANT_WRITE:
                VINBERO_COM_LOG_DEBUG("SSL_ERROR_WANT_WRITE");
                return VINBERO_COM_STATUS_AGAIN;
            case SSL_ERROR_WANT_READ:
                VINBERO_COM_LOG_DEBUG("SSL_ERROR_WANT_READ");
                return VINBERO_COM_STATUS_AGAIN;
            case SSL_ERROR_ZERO_RETURN:
                VINBERO_COM_LOG_ERROR("SSL_ERROR_ZERO_RETURN");
                break;
            case SSL_ERROR_SYSCALL:
                VINBERO_COM_LOG_ERROR("SSL_ERROR_SYSCALL");
                break;
            case SSL_ERROR_WANT_CONNECT:
                VINBERO_COM_LOG_ERROR("SSL_ERROR_WANT_CONNET");
                break;
            case SSL_ERROR_WANT_ACCEPT:
                VINBERO_COM_LOG_ERROR("SSL_ERROR_WANT_ACCEPT");
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                VINBERO_COM_LOG_ERROR("SSL_ERROR_WANT_X509_LOOKUP");
                break;
            case SSL_ERROR_SSL:
                VINBERO_COM_LOG_ERROR("SSL_ERROR_SSL");
                break;
            default:
                VINBERO_COM_LOG_ERROR("SSL_ERROR_???");
                break;
        }
        VINBERO_COM_LOG_ERROR("SSL_accept() failed");
        return VINBERO_COM_ERROR_UNKNOWN;
    }
    return VINBERO_COM_STATUS_SUCCESS;
}

int vinbero_iface_TLOCAL_rInit(struct vinbero_com_TlModule* tlModule) {
    return VINBERO_COM_STATUS_SUCCESS;
}

int vinbero_iface_MODULE_rInit(struct vinbero_com_Module* module) {
    return VINBERO_COM_STATUS_SUCCESS;
}

int vinbero_iface_CLOCAL_destroy(struct vinbero_com_ClModule* clModule) {
    VINBERO_COM_LOG_TRACE2();
    struct vinbero_mt_epoll_tls_ClModule* localClModule = clModule->localClModule.pointer;
    localClModule->clientIo.methods->close(&localClModule->clientIo);
    SSL_free(localClModule->ssl);
    return VINBERO_COM_STATUS_SUCCESS;
}

int vinbero_iface_TLOCAL_destroy(struct vinbero_com_TlModule* tlModule) {
    VINBERO_COM_LOG_TRACE2();
    return VINBERO_COM_STATUS_SUCCESS;
}

int vinbero_iface_TLOCAL_rDestroy(struct vinbero_com_TlModule* tlModule) {
    VINBERO_COM_LOG_TRACE2();
    return VINBERO_COM_STATUS_SUCCESS;
}


int vinbero_iface_MODULE_destroy(struct vinbero_com_Module* module) {
    return VINBERO_COM_STATUS_SUCCESS;
}

int vinbero_iface_MODULE_rDestroy(struct vinbero_com_Module* module) {
    VINBERO_COM_LOG_TRACE2();
    free(module->localModule.pointer);
    EVP_cleanup();
    return VINBERO_COM_STATUS_SUCCESS;
}
