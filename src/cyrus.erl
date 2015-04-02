-module(cyrus).
-export([client_new/3, client_start/2, client_step/2]).
-on_load(init/0).

-define(APPNAME, cyrus).
-define(LIBNAME, cyrus).

client_new(_, _, _) ->
    not_loaded(?LINE).

client_start(_, _) ->
    not_loaded(?LINE).

client_step(_, _) ->
    not_loaded(?LINE).

init() ->
    SoName = filename:join("./priv", ?LIBNAME),
    erlang:load_nif(SoName, 1).

not_loaded(Line) ->
    exit({not_loaded, [{module, ?MODULE}, {line, Line}]}).
