--TEST--
getAvailableCiphers() and getAvailableModes() (MCrypt)
--SKIPIF--
<?php include('skipif-mcrypt.inc'); ?>
--FILE--
<?php
$c = new \Phalcon\Ext\Crypt\MCrypt();
$ciphers = $c->getAvailableCiphers();
$modes   = $c->getAvailableModes();

assert(is_array($ciphers));
assert(is_array($modes));
?>
--EXPECT--
