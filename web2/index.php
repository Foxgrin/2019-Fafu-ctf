<!DOCTYPE html>
<!-- saved from url=(0027)http://123.206.31.85:49163/ -->
<html><head lang="en"><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  
  <title>FAFU管理系统</title>
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="format-detection" content="telephone=no">
  <meta name="renderer" content="webkit">
  <meta http-equiv="Cache-Control" content="no-siteapp">
  <link rel="stylesheet" href="./css/style.css">
  <style>
    .header {
      text-align: center;
    }
    .header h1 {
      font-size: 200%;
      color: #333;
      margin-top: 30px;
    }
    .header p {
      font-size: 14px;
    }
  </style>
</head>
<body>
<div class="header">
  <div class="am-g">
    <h1>FAFU管理系统</h1>
  </div>
  <hr>
</div>
<div class="am-g">
  <div class="am-u-lg-6 am-u-md-8 am-u-sm-centered">
    <h2>登录</h2>
    <p style="text-align:center;color:#1C86EE;font-size:20px;">
    	</p>
    <form method="post" class="am-form" action=''>
      <label for="uname">用户名:</label>
      <input type="text" name="username" id="email" value="">
      <br>
      <label for="password">密码:</label>
      <input type="password" name="password" id="password" value="">
      <br>
      <label for="remember-me">
        <input id="remember-me" type="checkbox">
        记住密码
      </label>
      <br>
      <div class="am-cf">
        <input type="submit" name="sub" value="登 录" class="am-btn am-btn-primary am-btn-sm am-fl">

      </div>
    </form>
    <hr>
    <p>© FAFU管理系统.</p>
  </div>
</div>

<?php 

include("flag.php");

error_reporting(0);
$con = mysql_connect('localhost','root','root');
if (!$con){
  echo "Failed to connect to MySQL: " . mysql_error();
}

@mysql_select_db('fafuctf',$con) or die ( "Unable to connect to the database.");

if(isset($_POST['username']) && isset($_POST['password'])){
  $username = $_POST['username'];
  $password = $_POST['password'];
  if(preg_match("/or|#|\|\||'/i",$password)) die("<p style='text-align:center;color:#1C86EE;font-size:20px;'>Illegal Character!!!</p>");
  $sql = "SELECT * FROM web2 WHERE username='$username' AND password='$password'";
  $result = mysql_query($sql);
  $row = mysql_fetch_array($result);
  if($row){
    if($row['password'] === sha1($password)){
      echo "<p style='text-align:center;color:#1C86EE;font-size:20px;'>".$flag."</p>";
    }
    else{
      echo "<p style='text-align:center;color:#1C86EE;font-size:20px;'>Wrong password for ".$row['username']."</p>";
    }
  }
  else{
    echo "<p style='text-align:center;color:#1C86EE;font-size:20px;'>Wrong username / password.</p>";
  }
}
else if (isset($_POST['sub'])){
  echo "<p style='text-align:center;color:#1C86EE;font-size:20px;'>Wrong username / password.</p>";
}

 ?>


</body></html>