--TEST--
Encryption/Decryption Test
--SKIPIF--
<?php include('skipif.inc'); ?>
--FILE--
<?php
$tests = array(
	mt_rand(0, 100) => 'Some text',
	md5(uniqid()) => str_repeat('x', mt_rand(1, 255)),
	time() => str_shuffle('abcdefeghijklmnopqrst'),
);

$crypt = new \Phalcon\Ext\Crypt\MCrypt();

foreach (array(MCRYPT_MODE_ECB, MCRYPT_MODE_CBC, MCRYPT_MODE_CFB, MCRYPT_MODE_CFB, MCRYPT_MODE_NOFB) as $mode) {
	$crypt->setMode($mode);

	foreach ($tests as $key => $test) {
		$crypt->setKey($key);
		$encrypted = $crypt->encrypt($test);
		assert(rtrim($crypt->decrypt($encrypted), "\0") === $test);
	}

	foreach ($tests as $key => $test) {
		$encrypted = $crypt->encrypt($test, $key);
		assert(rtrim($crypt->decrypt($encrypted, $key), "\0") === $test);
	}
}
--EXPECT--
