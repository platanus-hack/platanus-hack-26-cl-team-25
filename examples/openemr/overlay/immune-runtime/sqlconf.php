<?php

//  OpenEMR
//  MySQL Config (Inmune: from the environment, so prod, the shadow clones and the judge share one image)

$host   = getenv('MYSQL_HOST') ?: 'localhost';
$port   = getenv('MYSQL_PORT') ?: '3306';
$login  = getenv('MYSQL_USER') ?: 'openemr';
$pass   = getenv('MYSQL_PASS') ?: '';
$dbase  = getenv('MYSQL_DATABASE') ?: 'openemr';

$sqlconf = [];
global $sqlconf;
$sqlconf["host"]= $host;
$sqlconf["port"] = $port;
$sqlconf["login"] = $login;
$sqlconf["pass"] = $pass;
$sqlconf["dbase"] = $dbase;

$config = 1;
