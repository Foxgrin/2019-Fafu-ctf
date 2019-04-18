<?php
include 'class.php';
include 'waf.php';
if(@$_GET['page']){
	$page = $_GET['page'];
	waf($page);
}else{
	$page = "Passage";
}

if(@$_GET['id'] == 1){
	include 'passage/words.php';
}
$tips = @$_GET['tips'];
$tip  = @$_GET['tip'];
// echo $tips;
if(isset($tip)&&(@file_get_contents($tip,'r')==="you got this")){
	//echo 123;
	@unserialize($tips);
}



?>
<!DOCTYPE HTML>
<html>
<head>
	<title>Welcome To My Blog!</title>
	<link rel="stylesheet" href="http://libs.baidu.com/bootstrap/3.0.3/css/bootstrap.min.css" />
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
<nav class="navbar navbar-inverse navbar-fixed-top">
	<div class="container">
		<div id="navbar" class="collapse navbar-collapse">
			<ul class="nav nav-tabs">
				<li <?php  if($page=="Passage"){echo "class='active'";}?>><a href="?page=Passage">Passage</a></li>
				<li <?php  if($page=="About"  ){echo "class='active'";}?>><a href="?page=About"  >About  </a></li>
				<li <?php  if($page=="Link"   ){echo "class='active'";}?>><a href="?page=Link"   >Link   </a>></li>
				<li <?php  if($page=="Flag"   ){echo "class='active'";}?>><a href="?page=Flag&tips=yes"   >Flag   </a></li>
			</ul>
		</div>
	</div>
</nav>
<div class="container" style="margin-top: 200px">
<?php  

// $test = unserialize($testString);
if($page == "Passage"){
	require_once 'passage/title.php';
}else{
	if(!file_exists("./templates/$page.php")){
		die("No such file or directory!");
	}else{
		system("php ./templates/$page.php");
	}
}
?>
</div>
<script src="http://code.jquery.com/jquery-latest.js" />
<script src="http://libs.baidu.com/bootstrap/3.0.3/js/bootstrap.min.js" />
</body>
</html>
