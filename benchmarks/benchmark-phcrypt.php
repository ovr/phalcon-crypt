<?php

$before = memory_get_usage();

$s = str_repeat('a', 1048576*10);

$c = new \Phalcon\Ext\Crypt\MCrypt();
$c->setCipher('blowfish');
$c->setMode('ncfb');
$key = substr(md5('very secret key'), 0, 8);
$c->setKey($key);
$encrypted = $c->encrypt($s);

$after = memory_get_usage();
echo $after - $before, ' ', memory_get_peak_usage(), "\n";
