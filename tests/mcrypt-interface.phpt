--TEST--
Check whether Phalcon\CryptInterface is implemented (MCrypt)
--SKIPIF--
<?php if (!extension_loaded('phcrypt') || !extension_loaded('phalcon')) die('skip phalcon and phcrypt extensions required'); ?>
<?php include('skipif-mcrypt.inc'); ?>
--FILE--
<?php
$c = new \Phalcon\Ext\Crypt\MCrypt();
assert($c instanceof \Phalcon\CryptInterface);
?>
--EXPECT--
