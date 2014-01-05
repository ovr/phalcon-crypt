--TEST--
Serialize/unserialize (MCrypt)
--SKIPIF--
<?php include('skipif-mcrypt.inc'); ?>
--FILE--
<?php
$c = new \Phalcon\Ext\Crypt\MCrypt;

assert($c instanceof \Serializable);

try {
	$s = serialize($c);
	echo $s, PHP_EOL;
	assert(false);
}
catch (Exception $e) {
	echo $e->getMessage(), PHP_EOL;
}

try {
	$s = 'O:24:"Phalcon\\Ext\\Crypt\\MCrypt":0:{}';
	$c2 = unserialize($s);
	assert(false);
}
catch (Exception $e) {
	assert($e instanceof BadMethodCallException);
	echo $e->getMessage(), PHP_EOL;
}

try {
	$s = 'C:24:"Phalcon\\Ext\\Crypt\\MCrypt":0:{}';
	$c3 = @unserialize($s); // PHP up to 5.5 shows a notice here
	assert(false);
}
catch (Exception $e) {
	assert(!($e instanceof BadMethodCallException));
	echo $e->getMessage(), PHP_EOL;
}

// Test serialize() method
assert(null === $c->serialize());

// Test unserialize() method
try {
	$c->unserialize('bogus');
}
catch (Exception $e) {
	assert($e instanceof BadMethodCallException);
	echo $e->getMessage(), PHP_EOL;
}
?>
--EXPECT--
Serialization of 'Phalcon\Ext\Crypt\MCrypt' is not allowed
Unserialization of 'Phalcon\Ext\Crypt\MCrypt' is not allowed
Unserialization of 'Phalcon\Ext\Crypt\MCrypt' is not allowed
Unserialization of 'Phalcon\Ext\Crypt\MCrypt' is not allowed
