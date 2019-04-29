<?php

error_reporting(E_ALL);
ini_set("display_errors", 1);

session_start();
require_once 'db.php';
require_once 'user.php';

$db = new DB();

$username = $_POST['username'];
$passwd = $_POST['passwd'];


if ($res = $db->login($username, $passwd)) {
	$_SESSION['username'] = $username;
	$message = "<script>alert('login success'); location.href='/web37/';</script>";
	echo $message;
}
else{
	$message = "<script>alert('login fail'); location.href='/web37/';</script>";
	echo $message;
}