-module(ewt).
-include("ewt.hrl").
-define(TYPE, 'EWT').

-export([token/4, claims/2, token_dated/4, claims_dated/2]).

token_dated(Expiration, Claims_, Key, Alg) ->
	Now = integer_to_binary(calendar:datetime_to_gregorian_seconds(calendar:universal_time())),
	<<Now/binary, ".", (token(Expiration, Claims_, Key, Alg))/binary>>.

token(Expiration, Claims_, Key, Alg) ->
	Claims = Claims_#{exp => exp(Expiration)},
	Header = #{typ => ?TYPE, alg => alg(Alg)},

	B64Header = base64url:encode(term_to_binary(Header)),
	B64Claims = base64url:encode(term_to_binary(Claims)),

	HeaderClaims = <<B64Header/binary, ".", B64Claims/binary>>,

	B64Signature = sign(?TYPE, alg(Alg), B64Header, B64Claims, Key),

	<<HeaderClaims/binary, ".", B64Signature/binary>>.


claims_dated(Token, Key) ->
	case catch parse(Token, Key, dated) of
		expired -> expired;
		{ok, Claim} -> {ok, Claim};
		_ -> bad
	end.


claims(Token, Key) ->
	case catch parse(Token, Key) of
		expired -> expired;
		{ok, Claim} -> {ok, Claim};
		_ -> bad
	end.

parse(Token, Key, dated) ->
	[_Date, Rest] = binary:split(Token, <<".">>),
	parse(Rest, Key).

parse(Token, Key) ->
	[B64Header, B64Claims, B64Signature] = binary:split(Token, <<".">>, [global]),
	#{typ := Type, alg := Alg} = binary_to_term(base64url:decode(B64Header), [safe]),
	true = B64Signature == sign(Type, Alg, B64Header, B64Claims, Key),
	#{exp := Exp} = Claims = binary_to_term(base64url:decode(B64Claims), [safe]),
	Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
	if
		Now > Exp -> expired;
		true -> {ok, Claims}
	end.

sign(?TYPE, Alg, B64Header, B64Claims, Key) ->
	base64url:encode(crypto:hmac(Alg, Key, <<B64Header/binary, ".", B64Claims/binary>>)).



alg(auto) -> ?DEFAULT_ALG;
alg(Alg) -> Alg.

exp(auto) -> ?DEFAULT_EXP;
exp(Exp) -> Exp.