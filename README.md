HKDF
=====
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/aenglisc/hkdf_erlang/CI?style=for-the-badge)](https://github.com/aenglisc/hkdf_erlang/runs/801486938)
![Erlang](https://img.shields.io/badge/erlang-ANY-blue.svg?style=for-the-badge)
[![Hex.pm](https://img.shields.io/hexpm/v/hkdf_erlang.svg?style=for-the-badge)](https://hex.pm/packages/hkdf_erlang)

An implementation of [HKDF](https://tools.ietf.org/html/rfc5869) in Erlang.

Usage
-----

#### derive key
```erlang
OKM = hkdf:derive(sha384, <<"Never gonna give you up">>, 42).
```

#### extract key
```erlang
PRK = hkdf:extract(sha384, <<"Never gonna give you up">>).
```

#### expand key
```erlang
PRK = hkdf:extract(sha384, <<"Never gonna give you up">>).
OKM = hkdf:expand(sha384, PRK, 42).
```
