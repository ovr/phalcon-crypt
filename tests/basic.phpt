--TEST--
Basic test
--SKIPIF--
<?php include('skipif-mcrypt.inc'); ?>
--FILE--
<?php
$c = new \Phalcon\Ext\Crypt\MCrypt;
print_r($c);
echo $c->getCipher(), ' ', $c->getMode(), PHP_EOL;
var_export($c->getKey());
echo PHP_EOL;
$c->setCipher('des')->setMode('ecb')->setKey('supersecretkey');
echo $c->getCipher(), ' ', $c->getMode(), ' ', $c->getKey(), PHP_EOL;
print_r($c);
?>
--EXPECT--
Phalcon\Ext\Crypt\MCrypt Object
(
    [cipher] => blowfish
    [mode] => ncfb
    [key] => 
)
blowfish ncfb
''
des ecb supersecretkey
Phalcon\Ext\Crypt\MCrypt Object
(
    [cipher] => des
    [mode] => ecb
    [key] => [set]
)
