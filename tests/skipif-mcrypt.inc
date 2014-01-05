<?php if (!extension_loaded("phcrypt")) die("skip"); ?>
<?php if (!class_exists('\Phalcon\Ext\Crypt\MCrypt')) die("skip phcrypt built without MCrypt support"); ?>
