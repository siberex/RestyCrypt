<?php
require_once 'RestyCrypt.php';

$rc = new RestyCrypt(getenv('SESSION_KEY'), getenv('SESSION_IV'), 3600);

$text = empty($argv[1]) ? 'This is THE TEXT to be Encrypted!' : $argv[1];
echo $rc->encrypt($text);
