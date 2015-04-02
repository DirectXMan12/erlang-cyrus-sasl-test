#include "erl_nif.h"
#include "sasl/sasl.h"
#include "stdio.h"
#include "string.h"


ErlNifResourceType *SASL_CONN_TYPE;
ERL_NIF_TERM ATOM_SASL_CONN;
ERL_NIF_TERM ATOM_OK;
ERL_NIF_TERM ATOM_CONTINUE;
ERL_NIF_TERM ATOM_ERROR;

ERL_NIF_TERM make_sasl_err_str(ErlNifEnv *env, int err_code) {
    const char *err_string = sasl_errstring(err_code, NULL, NULL);
    return enif_make_tuple2(env, ATOM_ERROR, enif_make_tuple2(env,
            enif_make_int(env, err_code),
            enif_make_string(env, err_string, ERL_NIF_LATIN1)));
}

ERL_NIF_TERM make_sasl_err_detail(ErlNifEnv *env, int err_code, sasl_conn_t *conn) {
    const char *err_string = sasl_errdetail(conn);
    return enif_make_tuple2(env, ATOM_ERROR, enif_make_tuple2(env,
            enif_make_int(env, err_code),
            enif_make_string(env, err_string, ERL_NIF_LATIN1)));
}

// TODO(directxman12): the client_start and client_step methods should really
// be in threads (or eventually dirty NIFs), since they potentially block
// (while doing IO to perform the authentication)

ERL_NIF_TERM get_string(ErlNifEnv *env, ERL_NIF_TERM list, char **buff) {
    unsigned int len;
    char *str = NULL;

    if (!enif_get_list_length(env, list, &len)) {
        return enif_make_badarg(env);
    }

    str = malloc(len + 1);
    if (!str) {
        // return enif make appropriate error
        return enif_make_badarg(env);
    }

    if (!enif_get_string(env, list, str, len + 1, ERL_NIF_LATIN1)) {
        free(str);
        return enif_make_badarg(env);
    }

    *buff = str;

    return 0;
}

// TODO: do we need to use enif_consume_timeslice

static ERL_NIF_TERM nif_client_new(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    // args we support: service, fqdn, flags
    // actual args: service, fqdn, local ip (or none), remote ip (or none), cbs, flags
    // NB(directxman12): the argument just before flags would be "connection-specific callbacks",
    //                   but we don't support those for the moment
    //
    // output: conn ptr

    // can call without local and remote ip

    char *service_name = NULL;
    char *fqdn = NULL;
    ERL_NIF_TERM res_term;
    //char *local_ip = NULL;
    //char *remote_ip = NULL;
    //sasl_callback_t cbs;
    unsigned int flags;

    if (argc != 3) {
        return enif_make_badarg(env);
    }

    // flags
    if (!enif_get_uint(env, argv[2], &flags)) {
        return enif_make_badarg(env);
    }

    // service name
    res_term = get_string(env, argv[0], &service_name);
    if (res_term) {
        goto cleanup;
    }

    // fqdn
    res_term = get_string(env, argv[1], &fqdn);
    if (res_term) {
        goto cleanup;
    }

    sasl_conn_t **conn = enif_alloc_resource(SASL_CONN_TYPE, sizeof(sasl_conn_t *));

    int call_res = sasl_client_new(service_name, fqdn, NULL, NULL, NULL, flags, conn);
    //int call_res = sasl_client_new(service_name, "b", NULL, NULL, NULL, flags, conn);
    //int call_res = sasl_client_new("a", "b", NULL, NULL, NULL, 0, conn);

    if (call_res != SASL_OK) {
        res_term = make_sasl_err_str(env, call_res);
        goto cleanup;
    }

    ERL_NIF_TERM conn_term = enif_make_resource(env, conn);
    enif_release_resource(conn);

    res_term = enif_make_tuple2(env, ATOM_OK, enif_make_tuple2(env, ATOM_SASL_CONN, conn_term));

cleanup:
    free(service_name);
    free(fqdn);

    return res_term;
}

ERL_NIF_TERM get_conn(ErlNifEnv *env, ERL_NIF_TERM tuple, sasl_conn_t ***conn) {
    const ERL_NIF_TERM *conn_tuple;
    int conn_tuple_arity;

    if (!enif_get_tuple(env, tuple, &conn_tuple_arity, &conn_tuple)) {
        return enif_make_badarg(env);
    }

    if (conn_tuple_arity != 2 || conn_tuple[0] != ATOM_SASL_CONN) {
        return enif_make_badarg(env);
    }

    if (!enif_get_resource(env, conn_tuple[1], SASL_CONN_TYPE, (void **) conn)) {
        return enif_make_badarg(env);
    }

    if (conn == NULL || *conn == NULL) {
        return enif_make_badarg(env);
    }

    return 0;
}

static ERL_NIF_TERM nif_client_start(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    // args: conn, mechlist
    // output args: prompt_need (not supported), client_out, client_out_len, mech

    sasl_conn_t **conn = NULL;
    char *mechlist = NULL;  // TODO(sross): do we want to have this be a list of strings (and join them by spaces ourself?)

    const char *clientout = NULL;
    unsigned int clientout_len;
    const char *mech_used = NULL;
    // TODO(directxman12): have a way to pass this in?
    sasl_interact_t *interact = NULL;

    unsigned char *clientout_bin;
    ERL_NIF_TERM clientout_term;
    ERL_NIF_TERM status_type;
    ERL_NIF_TERM res_term;

    if (argc != 2) {
        return enif_make_badarg(env);
    }

    res_term = get_conn(env, argv[0], &conn);
    if (res_term) {
        return res_term;
    }

    res_term = get_string(env, argv[1], &mechlist);
    if (res_term) {
        return res_term;
    }

    int call_res = sasl_client_start(*conn, mechlist, &interact, &clientout, &clientout_len, &mech_used);

    if (call_res != SASL_OK && call_res != SASL_CONTINUE) {
        res_term = make_sasl_err_detail(env, call_res, *conn);
        goto cleanup;
    }

    clientout_bin = enif_make_new_binary(env, clientout_len, &clientout_term);
    memcpy(clientout_bin, clientout, clientout_len);

    if (call_res == SASL_OK) {
        status_type = ATOM_OK;
    } else {
        // status_type == ATOM_CONTINUE;
        status_type = ATOM_CONTINUE;
    }

    return enif_make_tuple2(env, status_type, enif_make_tuple2(env, clientout_term, enif_make_string(env, mech_used, ERL_NIF_LATIN1)));

cleanup:
    free(mechlist);
    return res_term;
}

static ERL_NIF_TERM nif_client_step(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    // args: conn, mechlist
    // output args: prompt_need (not supported), client_out, client_out_len, mech

    sasl_conn_t **conn = NULL;
    ErlNifBinary input_data;

    const char *clientout = NULL;
    unsigned int clientout_len;
    // TODO(directxman12): have a way to pass this in?
    sasl_interact_t *interact = NULL;

    unsigned char *clientout_bin;
    ERL_NIF_TERM clientout_term;
    ERL_NIF_TERM status_type;
    ERL_NIF_TERM res_term;

    if (argc != 2) {
        return enif_make_badarg(env);
    }

    res_term = get_conn(env, argv[0], &conn);
    if (res_term) {
        return res_term;
    }

    if (!enif_inspect_binary(env, argv[1], &input_data)) {
        return enif_make_badarg(env);
    }

    int call_res = sasl_client_step(*conn, (const char *)input_data.data, input_data.size, &interact, &clientout, &clientout_len);

    if (call_res != SASL_OK && call_res != SASL_CONTINUE) {
        return make_sasl_err_detail(env, call_res, *conn);
    }

    clientout_bin = enif_make_new_binary(env, clientout_len, &clientout_term);
    memcpy(clientout_bin, clientout, clientout_len);

    if (call_res == SASL_OK) {
        status_type = ATOM_OK;
    } else {
        // status_type == ATOM_CONTINUE;
        status_type = ATOM_CONTINUE;
    }

    return enif_make_tuple2(env, status_type, clientout_term);
}

static int is_ok_load_info(ErlNifEnv *env, ERL_NIF_TERM load_info) {
    int i;
    return enif_get_int(env, load_info, &i) && i == 1;
}

void free_conn(ErlNifEnv *env, void *obj) {
    sasl_dispose((sasl_conn_t **)obj);
}

static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
    if (!is_ok_load_info(env, load_info)) {
        return -1;
    }

    const char *mod_name = "cyrus";
    const char *name = "SASLConnection";
    ErlNifResourceFlags flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;

    SASL_CONN_TYPE = enif_open_resource_type(env, mod_name, name, free_conn, flags, NULL);
    if (SASL_CONN_TYPE == NULL) {
        return -1;
    }

    ATOM_OK = enif_make_atom(env, "ok");
    ATOM_ERROR = enif_make_atom(env, "error");
    ATOM_CONTINUE = enif_make_atom(env, "continue");
    ATOM_SASL_CONN = enif_make_atom(env, "sasl_conn");

    if (sasl_client_init(NULL) != SASL_OK) {
        return -1;
    }

    return 0;
}

static void unload(ErlNifEnv *env, void *priv_data) {
    sasl_done();
}


// client_init in erl_nif init?
static ErlNifFunc nif_funcs[] = {
    {"client_new", 3, nif_client_new},
    {"client_start", 2, nif_client_start},
    {"client_step", 2, nif_client_step},
};

ERL_NIF_INIT(cyrus, nif_funcs, load, NULL, NULL, unload)
