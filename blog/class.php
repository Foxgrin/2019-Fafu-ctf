<?php

class Blog{
	public $file="passage";
	public function __destruct(){
		$black = ['awk','-','sed','comm','diff','grep','cp','mv','nl','less','od','cat','head','tail','more','tac','rm','ls','tailf',' ','%','%0a','%0d','%00','ls','echo','ps','${IFS}','ifconfig','mkdir','cp','chmod','wget','curl','http','www','`','printf','>','<','sort'];

		foreach ($black as $key => $value) {
			if(stripos($this->file,$value)){
				die("Attack!");
			}
		 }
		//echo "\n".$this->page;
		system("php ./templates/$this->file.php");
	}
}
$b =new Blog();
//echo serialize($b);
unset($b);


?>

