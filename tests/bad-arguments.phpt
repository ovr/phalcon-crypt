--TEST--
Passing incorrect arguments
--SKIPIF--
<?php include('skipif.inc'); ?>
--FILE--
<?php
$c = new \Phalcon\Ext\Crypt\MCrypt();
$c->setCipher();
$c->setMode();
$c->setKey();
$c->getCipher(1);
$c->getMode(1);
$c->getKey(1);

$c->encrypt();
$c->decrypt();
$c->encryptBase64();
$c->decryptBase64();

$c->serialize('');
$c->__wakeup('');

var_dump($c->decryptBase64("bogus"));
var_dump($c->decrypt("bogus"));

$c->setKey('key');
$c->setCipher('bogus');
var_dump($c->encrypt('text'));
?>
--EXPECTF--
Warning: Phalcon\Ext\Crypt\MCrypt::setCipher() expects exactly 1 parameter, 0 given in %s on line %d

Warning: Phalcon\Ext\Crypt\MCrypt::setMode() expects exactly 1 parameter, 0 given in %s on line %d

Warning: Phalcon\Ext\Crypt\MCrypt::setKey() expects exactly 1 parameter, 0 given in %s on line %d

Warning: Wrong parameter count for Phalcon\Ext\Crypt\MCrypt::getCipher() in %s on line %d

Warning: Wrong parameter count for Phalcon\Ext\Crypt\MCrypt::getMode() in %s on line %d

Warning: Wrong parameter count for Phalcon\Ext\Crypt\MCrypt::getKey() in %s on line %d

Warning: Phalcon\Ext\Crypt\MCrypt::encrypt() expects at least 1 parameter, 0 given in %s on line %d

Warning: Phalcon\Ext\Crypt\MCrypt::decrypt() expects at least 1 parameter, 0 given in %s on line %d

Warning: Phalcon\Ext\Crypt\MCrypt::encryptBase64() expects at least 1 parameter, 0 given in %s on line %d

Warning: Phalcon\Ext\Crypt\MCrypt::decryptBase64() expects at least 1 parameter, 0 given in %s on line %d

Warning: Wrong parameter count for Phalcon\Ext\Crypt\MCrypt::serialize() in %s on line %d

Warning: Wrong parameter count for Phalcon\Ext\Crypt\MCrypt::__wakeup() in %s on line %d
bool(false)
bool(false)
bool(false)
