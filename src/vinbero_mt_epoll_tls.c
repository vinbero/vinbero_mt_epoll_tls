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
#include <vinbero/vinbero_Module.h>
#include <vinbero/vinbero_ClData.h>
#include <libgenc/genc_cast.h>
#include <libgenc/genc_List.h>
#include <vinbero/vinbero_IModule.h>
#include <vinbero/vinbero_ICLocal.h>
#include <vinbero/vinbero_IClService.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <gaio.h>

struct vinbero_mt_epoll_tls_Module {
    VINBERO_IBASE_FUNCTION_POINTERS;
    VINBERO_ICLOCAL_FUNCTION_POINTERS;
    VINBERO_ICLSERVICE_FUNCTION_POINTERS;
    SSL_CTX* sslContext;
    struct gaio_Methods ioMethods;
};

VINBERO_IBASE_FUNCTIONS;
VINBERO_ICLOCAL_FUNCTIONS;
VINBERO_ICLSERVICE_FUNCTIONS;

struct vinbero_mt_epoll_tls_TlModule {
    int state;
};

struct vinbero_mt_epoll_tls_ClData {
    SSL* ssl;
    struct gaio_Io clientIo;
};

static int vinbero_mt_epoll_tls_Ssl_read(struct gaio_Io* io, void* buffer, int readSize) {
    return SSL_read((SSL*)io->object.pointer, buffer, readSize);
}

static int vinbero_mt_epoll_tls_Ssl_write(struct gaio_Io* io, void* buffer, int writeSize) {
    return SSL_write((SSL*)io->object.pointer, buffer, writeSize);
}

static int vinbero_mt_epoll_tls_Ssl_sendfile(struct gaio_Io* outIo, struct gaio_Io* inIo, int* offset, int count) {
    outIo->methods->fcntl(outIo, F_SETFL, outIo->methods->fcntl(outIo, F_GETFL, 0) & ~O_NONBLOCK);
    char* buffer = malloc(count);
    inIo->methods->read(inIo, buffer, count);
    outIo->methods->write(outIo, buffer, count);
    free(buffer);
    outIo->methods->fcntl(outIo, F_SETFL, outIo->methods->fcntl(outIo, F_GETFL, 0) | O_NONBLOCK);
    return count;
}

static int vinbero_mt_epoll_tls_Ssl_fcntl(struct gaio_Io* io, int command, int argCount, ...) {
    va_list args;
    va_start(args, argCount);
    int returnValue = fcntl(SSL_get_fd((SSL*)io->object.pointer), command, argCount, args);
    va_end(args);
    return returnValue;
}

static int vinbero_mt_epoll_tls_Ssl_fstat(struct gaio_Io* io, struct stat* statBuffer) {
    return fstat(SSL_get_fd((SSL*)io->object.pointer), statBuffer);
}

static int vinbero_mt_epoll_tls_Ssl_fileno(struct gaio_Io* io) {
    return SSL_get_fd((SSL*)io->object.pointer);
}

static int vinbero_mt_epoll_tls_Ssl_close(struct gaio_Io* io) {
    SSL_shutdown((SSL*)io->object.pointer); 
    SSL_shutdown((SSL*)io->object.pointer);
    return close(SSL_get_fd((SSL*)io->object.pointer));
}

int vinbero_IModule_init(struct vinbero_Module_Config* moduleConfig, struct vinbero_Module_List* moduleList, void* args[]) {
warnx("%s: %u: %s", __FILE__, __LINE__, __FUNCTION__);
    struct vinbero_mt_epoll_tls_Module* localModule = module->localModule.pointer;

    SSL_load_error_strings();	
    ERR_load_crypto_strings();
    OpenSSL_add_ssl_algorithms();

    module->tlModuleKey = malloc(1 * sizeof(pthread_key_t)); 
    pthread_key_create(module->tlModuleKey, NULL);
    module->localModule.pointer = malloc(1 * sizeof(struct vinbero_mt_epoll_tls_Module));

    VINBERO_MODULE_DLOPEN(module, moduleConfig);
    VINBERO_IBASE_DLSYM(module, struct vinbero_mt_epoll_tls_Module);
    VINBERO_ICLOCAL_DLSYM(module, struct vinbero_mt_epoll_tls_Module);
    VINBERO_ICLSERVICE_DLSYM(module, struct vinbero_mt_epoll_tls_Module);

    localModule->sslContext = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_ecdh_auto(localModule->sslContext, 1);

    char* certificateFile;
    char* privateKeyFile;

    VINBERO_MODULE_GET_REQUIRED_CONFIG(moduleConfig, "vinbero_mt_epoll_tls.certificateFile", string, &certificateFile);
    if((certificateFile = realpath(certificateFile, NULL)) == NULL)
        err(EXIT_FAILURE, "%s: %u: ", __FILE__, __LINE__);

    VINBERO_MODULE_GET_REQUIRED_CONFIG(moduleConfig, "vinbero_mt_epoll_tls.privateKeyFile", string, &privateKeyFile);
    if((privateKeyFile = realpath(privateKeyFile, NULL)) == NULL)
        err(EXIT_FAILURE, "%s: %u: ", __FILE__, __LINE__);
 
    if(SSL_CTX_use_certificate_file(localModule->sslContext, certificateFile, SSL_FILETYPE_PEM) <= 0) {
        free(certificateFile);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if(SSL_CTX_use_PrivateKey_file(localModule->sslContext, privateKeyFile, SSL_FILETYPE_PEM) <= 0) {
        free(privateKeyFile);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    free(certificateFile);
    free(privateKeyFile);

    localModule->ioMethods.read = vinbero_mt_epoll_tls_Ssl_read;
    localModule->ioMethods.write = vinbero_mt_epoll_tls_Ssl_write;
    localModule->ioMethods.sendfile = vinbero_mt_epoll_tls_Ssl_sendfile;
    localModule->ioMethods.fcntl = vinbero_mt_epoll_tls_Ssl_fcntl;
    localModule->ioMethods.fstat = vinbero_mt_epoll_tls_Ssl_fstat;
    localModule->ioMethods.fileno = vinbero_mt_epoll_tls_Ssl_fileno;
    localModule->ioMethods.close = vinbero_mt_epoll_tls_Ssl_close;

    return 0;
}

int vinbero_ITLocal_init(struct vinbero_Module* module, struct vinbero_Module_Config* moduleConfig, void* args[]) {
warnx("%s: %u: %s", __FILE__, __LINE__, __FUNCTION__);
    struct vinbero_mt_epoll_tls_Module* localModule = module->localModule.pointer;
    struct vinbero_mt_epoll_tls_TlModule* tlModule = malloc(sizeof(struct vinbero_mt_epoll_tls_TlModule));
    tlModule->state = 0;
    pthread_setspecific(*module->tlModuleKey, tlModule);
    return localModule->vinbero_ITLocal_init(GENC_LIST_ELEMENT_NEXT(module), GENC_LIST_ELEMENT_NEXT(moduleConfig), (void*[]){NULL});
}

int vinbero_ICLocal_init(struct vinbero_Module* module, struct vinbero_ClData_List* clDataList, void* args[]) {
warnx("%s: %u: %s", __FILE__, __LINE__, __FUNCTION__);
    struct tucube_mt_epoll_tls_ClData* localClData = clData->generic.pointer;
    struct vinbero_mt_epoll_tls_Module* localModule = module->localModule.pointer;
    struct vinbero_ClData* clData = malloc(1 * sizeof(struct vinbero_ClData));
    struct gaio_Io* localClientIo = args[0];
    GENC_LIST_ELEMENT_INIT(clData);
    clData->generic.pointer = malloc(1 * sizeof(struct vinbero_mt_epoll_tls_ClData));
    localClData->ssl = SSL_new(GENC_CAST(module->localModule.pointer, struct vinbero_mt_epoll_tls_Module*)->sslContext);
    if(SSL_set_fd(localClData->ssl, dup(localClientIo->object.integer)) != 1) {
        warnx("%s: %u: SSL_set_fd() failed", __FILE__, __LINE__);
	return -1;
    }
    GENC_LIST_APPEND(clDataList, clData);
    localClData->clientIo.object.pointer = localClData->ssl;
    localClData->clientIo.methods = &(localModule->ioMethods);
    return localModule->vinbero_ICLocal_init(GENC_LIST_ELEMENT_NEXT(module), clDataList, (void*[]){&localClData->clientIo, NULL});
}

int vinbero_IClService_call(struct vinbero_Module* module, struct vinbero_ClData* clData, void* args[]) {
warnx("%s: %u: %s", __FILE__, __LINE__, __FUNCTION__);
    struct vinbero_mt_epoll_tls_Module* localModule = module->localModule.pointer;
    struct vinbero_mt_epoll_tls_TlModule* tlModule = pthread_getspecific(*module->tlModuleKey);
    struct tucube_mt_epoll_tls_ClData* localClData = clData->generic.pointer;


    if(SSL_is_init_finished(localClData->ssl))
        return localModule->vinbero_IClService_call(GENC_LIST_ELEMENT_NEXT(module), GENC_LIST_ELEMENT_NEXT(clData), (void*[]){NULL});

    int result;
    if((result = SSL_accept(localClData->ssl)) != 1) {
        switch(SSL_get_error(localClData->ssl, result)) {
            case SSL_ERROR_NONE:
	        warnx("%s: %u: SSL_ERROR_NONE", __FILE__, __LINE__);
		break;
	    case SSL_ERROR_WANT_WRITE:
	        warnx("%s: %u: SSL_ERROR_WANT_WRITE", __FILE__, __LINE__);
		return 1;
	    case SSL_ERROR_WANT_READ:
	        warnx("%s: %u: SSL_ERROR_WANT_READ", __FILE__, __LINE__);
		return 1;
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
	        warnx("%s: %u: SSL_ERROR_???", __FILE__, __LINE__);
		break;
        }
	warnx("%s: %u: SSL_accept() failed", __FILE__, __LINE__);
        return -1;
    }
}

int vinbero_ICLocal_destroy(struct vinbero_Module* module, struct vinbero_ClData* clData) {
    struct vinbero_mt_epoll_tls_Module* localModule = module->localModule.pointer;
    struct tucube_mt_epoll_tls_ClData* localClData = clData->generic.pointer;
    localModule->vinbero_ICLocal_destroy(GENC_LIST_ELEMENT_NEXT(module), GENC_LIST_ELEMENT_NEXT(clData));
    warnx("%s: %u: %s", __FILE__, __LINE__, __FUNCTION__);
    localClData->clientIo.methods->close(&localClData->clientIo);
    SSL_free(localClData->ssl);
}

int vinbero_ITLocal_destroy(struct vinbero_Module* module) {
warnx("%s: %u: %s", __FILE__, __LINE__, __FUNCTION__);
    struct vinbero_mt_epoll_tls_Module* localModule = module->localModule.pointer;
    return localModule->vinbero_ITLocal_destroy(GENC_LIST_ELEMENT_NEXT(module));
}

int vinbero_IModule_destroy(struct vinbero_Module* module) {
warnx("%s: %u: %s", __FILE__, __LINE__, __FUNCTION__);
    struct vinbero_mt_epoll_tls_Module* localModule = module->localModule.pointer;
    localModule->vinbero_IModule_destroy(GENC_LIST_ELEMENT_NEXT(module));
//    dlclose(module->dl_handle);
    free(module->localModule.pointer);
    free(module);
    EVP_cleanup();
    return 0;
}
