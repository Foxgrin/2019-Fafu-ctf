<?php

function waf($values){
	$black = ['rev','php','grep','mv','%','-','tailf','nl','less','|','$','$IFS$9','od','cat','head','tail','more','tac','rm','ls',';','tailf',' ','%','%0a','%0d','%00','ls','echo','ps','>','<','${IFS}','ifconfig','mkdir','cp','chmod','wget','curl','http','www','`','printf','awk'];
	foreach ($black as $key => $value) {
		if(stripos($values,$value)){
			die("Attack!");
		}
	}
}

?>