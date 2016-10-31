# śarkarā
[![travis ci](https://api.travis-ci.org/quininer/sarkara.svg)](https://travis-ci.org/quininer/sarkara)
[![crates](https://img.shields.io/crates/v/sarkara.svg)](https://crates.io/crates/sarkara)
[![license](https://img.shields.io/github/license/quininer/sarkara.svg)](https://github.com/quininer/sarkara/blob/master/LICENSE)
[![clippy](https://clippy.bashy.io/github/quininer/sarkara/master/badge.svg)](https://clippy.bashy.io/github/quininer/sarkara/master/log)
[![docs.rs](https://docs.rs/sarkara/badge.svg)](https://docs.rs/sarkara/)

Sarkara is a Post-Quantum cryptography library.

**This is an experimental library, don't use it in production environment.**


Public-key cryptography
-----------------------

* Authenticated encryption
	+ [x] `newhope-ascon`
	+ [x] `newhope-hc256hmacblake2`
	+ [x] `newhope-hc256rivblake2`
* Signatures
	+ [x] [bliss](http://bliss.di.ens.fr/)
* Key exchange
	+ [x] [newhope](https://eprint.iacr.org/2015/1092)

Secret-key cryptography
-----------------------

* Authenticated encryption
	+ [x] [ascon (if it is CAESAR winner)](http://ascon.iaik.tugraz.at/)
	+ [x] `hc256hmacblake2`
	+ [x] `hc256rivblake2`
* Encryption
	+ [x] [hc256](http://www.ecrypt.eu.org/stream/hcpf.html)
* Authentication
	+ [x] `HMAC (nonce variant)`
* Key derivation
	+ [x] [argon2](https://password-hashing.net/)

Low-level functions
-------------------

* Hashing
	+ [x] [blake2](https://blake2.net/)


Reference
---------

* [Breaking Symmetric Cryptosystems using Quantum Period Finding](https://arxiv.org/pdf/1602.05973)
* [Quantum-Secure Message Authentication Codes](http://eprint.iacr.org/2012/606.pdf)
* [Post-quantum security models for authenticated encryption](http://cacr.uwaterloo.ca/techreports/2016/cacr2016-04.pdf)
* [Post-quantum security models for authenticated encryption (talk ppt)](https://pqcrypto2016.jp/data/Soukharev-talk3.pdf)
* [Post-Quantum Cryptography: NIST's Plan for the Future - PQCrypto 2016](https://pqcrypto2016.jp/data/pqc2016_nist_announcement.pdf)
* [Experimenting with Post-Quantum Cryptography](https://security.googleblog.com/2016/07/experimenting-with-post-quantum.html)
* [The BRUTUS automatic cryptanalytic framework](https://link.springer.com/article/10.1007%2Fs13389-015-0114-1)
* [RIV for Robust Authenticated Encryption](https://fse.rub.de/slides/fse_talk_lucks.pdf)
