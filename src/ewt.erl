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

	Payload = payload(B64Header, B64Claims),

	B64Signature = sign(?TYPE, alg(Alg), Payload, Key),

	<<Payload/binary, ".", B64Signature/binary>>.


claims_dated(Token, Key) ->
	claims(Token, Key, dated).


claims(Token, Key) ->
	claims(Token, Key, standard).

claims(Token, Key, Mode) ->
	case catch parse(Token, Key, Mode) of
		expired -> expired;
		{ok, Claim} -> {ok, Claim};
		_ -> bad
	end.


parse(Token, Key, dated) ->
	[_Date, Rest] = binary:split(Token, <<".">>),
	parse(Rest, Key, standard);

parse(Token, Key, standard) ->
	[B64Header, B64Claims, B64Signature] = binary:split(Token, <<".">>, [global]),
	#{typ := Type, alg := Alg} = binary_to_term(base64url:decode(B64Header), [safe]),
	true = B64Signature == sign(Type, Alg, B64Header, B64Claims, Key),
	Claims = binary_to_term(base64url:decode(B64Claims), [safe]),
	check_expired(Claims).


check_expired(#{exp := Exp} = Claims) ->
	Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
	check_expired(Claims, Now, Exp).

check_expired(_Claims, Now, Exp) when Now > Exp -> expired;
check_expired(Claims, _Now, _Exp) -> {ok, Claims}.

sign(?TYPE, Alg, Header, Claims, Key) ->
	Payload = payload(Header, Claims),
	sign(?TYPE, Alg, Payload, Key).
sign(?TYPE, Alg, Payload, Key) ->
	base64url:encode(crypto:hmac(Alg, Key, Payload)).

payload(Header, Claims) ->
	<<Header/binary, ".", Claims/binary>>.

alg(auto) -> ?DEFAULT_ALG;
alg(Alg) -> Alg.

exp(auto) -> ?DEFAULT_EXP;
exp(Exp) -> Exp.