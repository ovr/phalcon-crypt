--TEST--
getAvailableCiphers() and getAvailableModes()
--SKIPIF--
<?php include('skipif.inc'); ?>
--FILE--
<?php
$c = new \Phalcon\Ext\Crypt\MCrypt();
$ciphers = $c->getAvailableCiphers();
$modes   = $c->getAvailableModes();

assert(is_array($ciphers));
assert(is_array($modes));
?>
--EXPECT--
