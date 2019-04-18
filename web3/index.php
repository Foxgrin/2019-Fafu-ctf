<?php 

error_reporting(0);

if(!isset($_GET['file'])){
	header("hint:include($_GET['file'])");
	include('heicore.html');
}

$user = $_GET["user"];
$file = $_GET["file"];
$pass = $_GET["pass"];
if(isset($user)&&(file_get_contents($user,'r')==="the user is admin")){
	echo "hello admin!<br>";
	if(preg_match("/f1a9/",$file)){
		exit();
	}else{
		include($file); //class.php
		$pass = unserialize($pass);
		echo $pass;
	}
}else{
	echo "you are not admin ! ";
}


 ?>