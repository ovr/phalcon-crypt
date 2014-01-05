# phalcon-crypt [![Build Status](https://travis-ci.org/sjinks/phalcon-crypt.png?branch=master)](https://travis-ci.org/sjinks/phalcon-crypt)

Faster version of Phalcon\Crypt using native libmcrypt/openssl instead of mcrypt and openssl PHP extensions.

Main features:
  * speed;
  * lower memory consumption.

**Memory Consumption:**

A 10 megabyte string was encrypted with Blowfish in nCFB mode.

  * mcrypt:
    * memory usage: 20,972,512 bytes
    * peak usage: 31,692,832 bytes
  * Phalcon\Crypt (1.3.0):
    * memory usage: 20,972,672 bytes
    * peak usage: 42,179,984 bytes
  * phcrypt (Phalcon\Ext\Crypt\MCrypt):
    * memory usage: 20,972,520 bytes
    * peak usage: 21,208,240 bytes
