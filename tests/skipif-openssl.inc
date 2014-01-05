<?php if (!extension_loaded("phcrypt")) die("skip"); ?>
<?php if (!class_exists('\Phalcon\Ext\Crypt\OpenSSL')) die("skip phcrypt built without OpenSSL support"); ?>
