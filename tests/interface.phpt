--TEST--
Check whether Phalcon\CryptInterface is implemented
--SKIPIF--
<?php if (!extension_loaded('phcrypt') || !extension_loaded('phalcon')) die('skip phalcon and phcrypt extensions required'); ?>
--FILE--
<?php
$c = new \Phalcon\Ext\Crypt\MCrypt();
assert($c instanceof \Phalcon\CryptInterface);
?>
--EXPECT--
