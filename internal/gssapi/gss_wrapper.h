//+build gssapi
//+build linux darwin
#ifndef GSS_WRAPPER_H
#define GSS_WRAPPER_H

#include <stdlib.h>
#ifdef GOOS_linux
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif
#ifdef GOOS_darwin
#include <GSS/GSS.h>
#endif

#define GSSAPI_OK_2 0
#define GSSAPI_CONTINUE_2 1
#define GSSAPI_ERROR_2 2

typedef struct {
    gss_name_t spn;
    gss_cred_id_t cred;
    gss_ctx_id_t ctx;

    OM_uint32 maj_stat;
    OM_uint32 min_stat;
} gssapi_client_state2;

int gssapi_error_desc2(
    OM_uint32 maj_stat, 
    OM_uint32 min_stat, 
    char **desc
);

int gssapi_client_init2(
    gssapi_client_state2 *client,
    char* spn,
    char* username,
    char* password
);

int gssapi_client_username2(
    gssapi_client_state2 *client,
    char** username
);

int gssapi_client_negotiate2(
    gssapi_client_state2 *client,
    void* input,
    size_t input_length,
    void** output,
    size_t* output_length
);

int gssapi_client_wrap_msg2(
    gssapi_client_state2 *client,
    void* input,
    size_t input_length,
    void** output,
    size_t* output_length 
);

int gssapi_client_destroy2(
    gssapi_client_state2 *client
);

#endif
