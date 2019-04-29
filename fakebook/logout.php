<?php 
session_start();
if(isset($_SESSION['username'])){
	session_destroy();
}
$message = "<script>alert('logout success'); location.href='/web37/';</script>";
echo $message;
