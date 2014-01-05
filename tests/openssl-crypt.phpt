--TEST--
Encryption/Decryption Test (OpenSSL)
--SKIPIF--
<?php include('skipif-openssl.inc'); ?>
--FILE--
<?php
$tests = array(
	mt_rand(0, 100) => 'Some text',
	md5(uniqid()) => str_repeat('x', mt_rand(1, 255)),
	time() => str_shuffle('abcdefeghijklmnopqrst'),
);

$crypt = new \Phalcon\Ext\Crypt\OpenSSL();

foreach ($crypt->getAvailableCiphers() as $cipher) {
	if (preg_match('/-(XTS|GCM|CCM)$/i', $cipher)) {
	// These nodes need special treatment, see
	// http://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
	// http://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Notes_on_some_unusual_modes
		continue;
	}

	if (strtoupper($cipher) == 'DES-EDE3-CFB1') {
	// There is a known bug in the OpenSSL implementation:
	// https://raw.github.com/openembedded/oe-core/master/meta/recipes-connectivity/openssl/openssl-1.0.1e/fix-cipher-des-ede3-cfb1.patch
		continue;
	}

	if (preg_match('/^AES-(?:256|128)-CBC-HMAC-SHA1$/i', $cipher)) {
	// These ones lead to a segmentation fault.
	// Could be a bug in OpenSSL
	// See
	//  * https://github.com/jruby/jruby/issues/919
	//  * https://bugs.ruby-lang.org/issues/8690
		continue;
	}

	$crypt->setCipher($cipher);

	foreach ($tests as $key => $test) {
		$crypt->setKey($key);
		$encrypted = $crypt->encrypt($test);
		$decrypted = $crypt->decrypt($encrypted);
		if ($decrypted !== $test) {
			echo $cipher, PHP_EOL;
		}
	}

	foreach ($tests as $key => $test) {
		$encrypted = $crypt->encrypt($test, $key);
		$decrypted = $crypt->decrypt($encrypted, $key);
		if ($decrypted !== $test) {
			echo $cipher, PHP_EOL;
		}
	}

}
?>
--EXPECT--
