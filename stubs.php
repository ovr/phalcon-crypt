<?php

namespace Phalcon\Ext\Crypt;

class MCrypt implements \Phalcon\CryptInterface, \Serializable
{
	public function __construct();

	/**
	 * @return string
	 */
	public function getCipher();

	/**
	 * @params string $cipher
	 */
	public function setCipher($cipher);

	/**
	 * @return string
	 */
	public function getMode();

	/**
	 * @params string $mode
	 */
	public function setMode($mode);

	/**
	 * @return string
	 */
	public function getKey();

	/**
	 * @params string $key
	 */
	public function setKey($key);

	/**
	 * @param string $text Plaintext
	 * @param string $key Key
	 * @return string|boolean
	 */
	public function encryptBase64($text, $key = null);

	/**
	 * @param string $text Ciphertext encoded with BASE64
	 * @param string $key Key
	 * @return string|boolean
	 */
	public function decryptBase64($text, $key = null);

	/**
	 * @return array
	 */
	public function getAvailableCiphers();

	/**
	 * @return array
	 */
	public function getAvailableModes();

	/**
	 * @return null
	 */
	public function serialize();

	/**
	 * @param string $str
	 * @throw BadMethodCallException
	 */
	public function unserialize($str);
}
