HKDF
=====
![CI](https://github.com/aenglisc/hkdf_erlang/workflows/CI/badge.svg)
![Erlang](https://img.shields.io/badge/erlang-22+-blue.svg)

An implementation of [HKDF](https://tools.ietf.org/html/rfc5869) in Erlang.

Requirements
-----

 - `Erlang 22+`

Usage
-----

```erlang
1> hkdf:derive_secrets(sha384, <<"Never gonna give you up">>, 42).
<<154,213,106,190,144,171,247,34,102,254,161,207,161,219,
  40,210,151,23,28,202,140,49,200,175,227,10,30,1,230,...>>
```
