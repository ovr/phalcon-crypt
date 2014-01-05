--TEST--
PKCS-7 padding
--SKIPIF--
<?php include('skipif-mcrypt.inc'); ?>
--FILE--
<?php

$texts = array();
$key   = '0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF';

$c       = new \Phalcon\Ext\Crypt\MCrypt();
$modes   = $c->getAvailableModes();
$ciphers = $c->getAvailableCiphers();

foreach ($modes as $key => $mode) {
	if (!$c->isBlockCipherMode($mode)) {
		unset($modes[$key]);
	}
}

foreach ($ciphers as $key => $cipher) {
	if (!$c->isBlockCipher($cipher)) {
		unset($ciphers[$key]);
	}
}

for ($i=1; $i<256; ++$i) {
	$texts[] = str_repeat('A', $i);
}

foreach ($ciphers as $cipher) {
	$c->setCipher($cipher)->setKey($key);

	foreach ($modes as $mode) {
		$c->setMode($mode);
		if ($c->isBlockMode()) {
			foreach ($texts as $text) {
				$encrypted = $c->encrypt($text);
				$actual    = $c->decrypt($encrypted);

				assert(gettype($encrypted) == 'string');
				assert(gettype($actual) == 'string');
				assert($actual == $text);

				if (!$c->isBlockMode()) {
					assert(strlen($encrypted) == strlen($actual));
				}
				else {
					assert(strlen($encrypted) > strlen($actual));
				}
			}
		}
	}
}
?>
--EXPECT--
