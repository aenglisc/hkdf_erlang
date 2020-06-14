%%=========================================================================
%% @author Roman Pushkov <pushkovroman@me.com>
%% @copyright (C) 2020, Roman Pushkov
%%
%% @doc
%% HKDF implementation in Erlang.
%% See more at [https://tools.ietf.org/html/rfc5869]
%% @end
%%=========================================================================
-module(hkdf).

-export(
  [ derive/3
  , derive/4
  , derive/5
  , extract/2
  , extract/3
  , expand/3
  , expand/4
  ]).

-type hash()
  :: md5
   | sha
   | sha224
   | sha256
   | sha384
   | sha512
   .

-define(DEFAULT_SALT(Hash), <<0:(hash_length(Hash))>>).

%%=========================================================================
%% API functions
%%=========================================================================

%%=========================================================================
%% @doc
%% The derivation function.
%%
%% Extracts a pseudorandom key from an input keying material and expands
%% it into an output keying material.
%%
%% See the respective functions for details.
%% @end
%%=========================================================================
-spec derive(Hash, IKM, L)
  -> OKM
when Hash :: hash()
   , IKM  :: binary()
   , L    :: pos_integer()
   , OKM  :: binary().
derive(Hash, IKM, L)
  -> derive(Hash, IKM, <<>>, ?DEFAULT_SALT(Hash), L).

-spec derive(Hash, IKM, Info, L)
  -> OKM
when Hash :: hash()
   , IKM  :: binary()
   , Info :: binary()
   , L    :: pos_integer()
   , OKM  :: binary().
derive(Hash, IKM, Info, L)
  -> derive(Hash, IKM, Info, ?DEFAULT_SALT(Hash), L).

-spec derive(Hash, IKM, Info, Salt, L)
  -> OKM
when Hash :: hash()
   , IKM  :: binary()
   , Info :: binary()
   , Salt :: binary()
   , L    :: pos_integer()
   , OKM  :: binary().
derive(Hash, IKM, Info, Salt, L)
  -> expand(Hash, extract(Hash, Salt, IKM), Info, L).

%%=========================================================================
%% @doc
%% The extraction function.
%%
%% ```
%% HKDF-Extract(salt, IKM) -> PRK
%% Options:
%%    Hash     a hash function; HashLen denotes the length of the
%%             hash function output in octets
%%
%% Inputs:
%%    salt     optional salt value (a non-secret random value);
%%             if not provided, it is set to a string of HashLen zeros.
%%    IKM      input keying material
%%
%% Output:
%%    PRK      a pseudorandom key (of HashLen octets)
%%
%% The output PRK is calculated as follows:
%%
%% PRK = HMAC-Hash(salt, IKM)
%% '''
%% @end
%%=========================================================================
-spec extract(Hash, IKM)
  -> PRK
when Hash :: hash()
   , IKM  :: binary()
   , PRK  :: binary().
extract(Hash, IKM)
  -> extract(Hash, ?DEFAULT_SALT(Hash), IKM).

-spec extract(Hash, Salt, IKM)
  -> PRK
when Hash :: hash()
   , Salt :: binary()
   , IKM  :: binary()
   , PRK  :: binary().
extract(Hash, Salt, IKM)
  -> extract_(Hash, Salt, IKM).

%%=========================================================================
%% @doc
%% The expansion function.
%%
%% ```
%% HKDF-Expand(PRK, info, L) -> OKM
%%
%% Options:
%%    Hash     a hash function; HashLen denotes the length of the
%%             hash function output in octets
%% Inputs:
%%    PRK      a pseudorandom key of at least HashLen octets
%%             (usually, the output from the extract step)
%%    info     optional context and application specific information
%%             (can be a zero-length string)
%%    L        length of output keying material in octets
%%             (<= 255*HashLen)
%%
%% Output:
%%    OKM      output keying material (of L octets)
%%
%% The output OKM is calculated as follows:
%%
%% N = ceil(L/HashLen)
%% T = T(1) | T(2) | T(3) | ... | T(N)
%% OKM = first L octets of T
%%
%% where:
%% T(0) = empty string (zero length)
%% T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
%% T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
%% T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
%% ...
%%
%% (where the constant concatenated to the end of each T(n) is a
%% single octet.)
%% '''
%% @end
%%=========================================================================
-spec expand(Hash, PRK, L)
  -> OKM
when Hash :: hash()
   , PRK  :: binary()
   , L    :: pos_integer()
   , OKM  :: binary().
expand(Hash, PRK, L)
  -> expand(Hash, PRK, <<>>, L).

-spec expand(Hash, PRK, Info, L)
  -> OKM
when Hash :: hash()
   , PRK  :: binary()
   , Info :: binary()
   , L    :: pos_integer()
   , OKM  :: binary().
expand(Hash, PRK, Info, L)
  -> expand_(Hash, PRK, Info, L).

%%=========================================================================
%% Internal functions
%%=========================================================================

-spec hash_length(Hash)
  -> HashLength
when Hash :: hash()
   , HashLength :: pos_integer().
hash_length(md5)
  -> 128 bsr 3;
hash_length(sha)
  -> 128 bsr 3;
hash_length(sha224)
  -> 224 bsr 3;
hash_length(sha256)
  -> 256 bsr 3;
hash_length(sha384)
  -> 384 bsr 3;
hash_length(sha512)
  -> 512 bsr 3.

-spec extract_(Hash, Salt, IKM)
  -> PRK
when Hash :: hash()
   , Salt :: binary()
   , IKM  :: binary()
   , PRK  :: binary().
extract_(Hash, Salt, IKM)
when not is_atom(Hash)
   , not is_binary(Salt)
   , not is_binary(IKM)
  -> error(badarg);
extract_(Hash, Salt, IKM)
  -> crypto:mac(hmac, Hash, Salt, IKM).

-spec expand_(Hash, PRK, Info, L)
  -> OKM
when Hash :: hash()
   , PRK  :: binary()
   , Info :: binary()
   , L    :: pos_integer()
   , OKM  :: binary().
expand_(Hash, PRK, Info, L)
when not is_atom(Hash)
   , not is_binary(PRK)
   , not is_binary(Info)
   , not is_integer(L), L =< 0
  -> error(badarg);
expand_(Hash, PRK, Info, L)
  -> ok = validate_length(Hash, L)
   , N = round(math:ceil(L/hash_length(Hash)))
   , Expander = expander(Hash, PRK, Info, L, N)
   , T0 = <<>>
   , Acc = <<>>
   , lists:foldl(Expander, {T0, Acc}, lists:seq(1, N))
   .

-spec validate_length(Hash, L)
  -> ok
when Hash :: hash()
   , L    :: pos_integer().
validate_length(Hash, L)
  -> hash_length(Hash) * 255 >= L orelse error(badlength)
   , ok
   .

-spec expander(Hash, PRK, Info, L, N)
  -> fun((I, {Ti, Acc}) -> {Ti, Acc} | OKM)
when Hash :: hash()
   , PRK  :: binary()
   , Info :: binary()
   , L    :: pos_integer()
   , N    :: pos_integer()
   , I    :: pos_integer()
   , Ti   :: binary()
   , Acc  :: binary()
   , OKM  :: binary().
expander(Hash, PRK, Info, L, N)
  -> fun
     (I, {TPrev, Acc}) when I =/= N
       -> Ti = crypto:mac(hmac, Hash, PRK, <<TPrev/binary, Info/binary, I:8>>)
        , {Ti, <<Acc/binary, Ti/binary>>}
        ;
     (I, {TPrev, Acc}) when I =:= N
       -> Ti = crypto:mac(hmac, Hash, PRK, <<TPrev/binary, Info/binary, I:8>>)
        , OKM = <<Acc/binary, Ti/binary>>
        , <<OKM:L/binary>>
     end.
