# Simple Sketch

## Elastic Sketch

梳理一下流程。

数据结构：

控制流：

Parser按端口区分ipv4和ethernet，按ipv4报头的protocol区分query与否。
这里的问题在于为什么要把一部分query放ipv4的optional里。
似乎真没必要....

Ingress简单的指定了转发端口。

CountQuery似乎就是个普通查询？封装了一下罢了。

MyEgress：若不是query，将本次的写入，且将结果写入meta。
但你这个meta哪来的...也许是本地定义吧，当作本地变量来用。
query则用CountQuery问一遍，同样写入meta-> hdr.query.count.

----

所以epoch应该是controller实现的。好事。

## 修改点

1. Sketch修改。先修改个最简单版本。
2. 脚本修改，得改出来一个单一集中的controller，定期试验他个几千次那种。
3. 先做这两个吧。

## 算法

controller实际上是能够获取所有流的信息的，设个classifer：大流用CountMin，小流用矩阵压缩。
至于classifier，理论上可以用controller更新BF，用BF判断是否大流。
非大流则发送CPU Port。

因此controller需要做到：
1. 定期发送更新报文，让CountMin信息定期上传。
2. 接受switch的小流报告，用矩阵压缩的形式保存内容。

receive/sender需要读取trace不断发送。

压缩感知这个后面测空间，连带着CountMin一起。
