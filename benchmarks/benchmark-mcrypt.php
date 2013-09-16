<?php

$before = memory_get_usage();

$s = str_repeat('a', 1048576*10);

$td = mcrypt_module_open('blowfish', '', 'ncfb', '');
$iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_DEV_URANDOM);
$key = substr(md5('very secret key'), 0, 8);
mcrypt_generic_init($td, $key, $iv);
$encrypted = mcrypt_generic($td, $s);
mcrypt_generic_deinit($td);
mcrypt_module_close($td);

$after = memory_get_usage();
echo $after - $before, ' ', memory_get_peak_usage(), "\n";