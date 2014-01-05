--TEST--
getAvailableCiphers() and getAvailableModes() (OpenSSL)
--SKIPIF--
<?php include('skipif-openssl.inc'); ?>
--FILE--
<?php
$c = new \Phalcon\Ext\Crypt\OpenSSL();
$ciphers = $c->getAvailableCiphers();
$modes   = $c->getAvailableModes();

assert(is_array($ciphers));
assert(is_array($modes));
assert(empty($modes));
?>
--EXPECT--
