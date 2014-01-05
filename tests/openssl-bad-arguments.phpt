--TEST--
Passing incorrect arguments (OpenSSL)
--SKIPIF--
<?php include('skipif-openssl.inc'); ?>
--FILE--
<?php
$c = new \Phalcon\Ext\Crypt\OpenSSL();
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
?>
--EXPECTF--
Warning: Phalcon\Ext\Crypt\OpenSSL::setCipher() expects exactly 1 parameter, 0 given in %s on line %d

Warning: Phalcon\Ext\Crypt\OpenSSL::setMode() expects exactly 1 parameter, 0 given in %s on line %d

Warning: Phalcon\Ext\Crypt\OpenSSL::setKey() expects exactly 1 parameter, 0 given in %s on line %d

Warning: Wrong parameter count for Phalcon\Ext\Crypt\OpenSSL::getCipher() in %s on line %d

Warning: Wrong parameter count for Phalcon\Ext\Crypt\OpenSSL::getMode() in %s on line %d

Warning: Wrong parameter count for Phalcon\Ext\Crypt\OpenSSL::getKey() in %s on line %d

Warning: Phalcon\Ext\Crypt\OpenSSL::encrypt() expects at least 1 parameter, 0 given in %s on line %d

Warning: Phalcon\Ext\Crypt\OpenSSL::decrypt() expects at least 1 parameter, 0 given in %s on line %d

Warning: Phalcon\Ext\Crypt\OpenSSL::encryptBase64() expects at least 1 parameter, 0 given in %s on line %d

Warning: Phalcon\Ext\Crypt\OpenSSL::decryptBase64() expects at least 1 parameter, 0 given in %s on line %d

Warning: Wrong parameter count for Phalcon\Ext\Crypt\OpenSSL::serialize() in %s on line %d

Warning: Wrong parameter count for Phalcon\Ext\Crypt\OpenSSL::__wakeup() in %s on line %d
bool(false)
bool(false)

Warning: Phalcon\Ext\Crypt\OpenSSL::setCipher(): Unknown cipher algorithm in %s on line %d
