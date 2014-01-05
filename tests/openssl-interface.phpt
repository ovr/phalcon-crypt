--TEST--
Check whether Phalcon\CryptInterface is implemented (OpenSSL)
--SKIPIF--
<?php if (!extension_loaded('phcrypt') || !extension_loaded('phalcon')) die('skip phalcon and phcrypt extensions required'); ?>
<?php include('skipif-openssl.inc'); ?>
--FILE--
<?php
$c = new \Phalcon\Ext\Crypt\OpenSSL();
assert($c instanceof \Phalcon\CryptInterface);
?>
--EXPECT--
