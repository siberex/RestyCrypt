<?php
require_once 'RestyCrypt.php';

$rc = new RestyCrypt($_ENV['SESSION_KEY'], $_ENV['SESSION_IV'], 3600);

$cipher = $argv[1] ?: 'lINbAuh1GsUUhV+60Pi+fTeJYUbajr6b51BnJ2dbkreLK7jKv/TkaAYbLot8HRpfPUuUfV8jmjyBHNOCeTNDkg==';
echo $rc->decrypt($cipher);
