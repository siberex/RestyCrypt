<?php
require_once 'RestyCrypt.php';

$rc = new RestyCrypt(getenv('SESSION_KEY'), getenv('SESSION_IV'), 3600);

$text = $argv[1] ?: 'This is THE TEXT to be Encrypted!';
echo $rc->encrypt($text);
