# 实验名称
SM2 implementation

# 实验简介
基于Miracl库实现SM2加密算法

# 实验完成人
权周雨 

学号：202000460021 

git账户名称：baekhunee

# Miracl库
MIRACL(Multiprecision Integer and Rational Arithmetic C/c++ Library)是一套由Shamus Software Ltd.所开发的一套关于大数运算函数库，用来设计与大数运算相关的密码学之应用，包含了RSA 公开密码学、Diffie-Hellman密钥交换(Key Exchange)、AES、DSA数字签名，还包含了较新的椭圆曲线密码学(Elliptic Curve Cryptography)等，运算速度快，并提供源代码。

本次实验基于Miracl库实现SM2，需要自行下载源码在VS2019中搭建，总体过程较为顺利，在此不过多赘述。

# SM2
SM2是一种非对称加密算法。它基于椭圆曲线密码的公钥密码算法标准，密钥长度为256bit，包含数字签名、密钥交换和公钥加密，可以满足电子认证服务系统等应用需求。SM2采用的是ECC 256位的一种，其安全强度比RSA 2048位高，且运算速度快于RSA。

## 算法流程
### 获取公私钥
![image](https://user-images.githubusercontent.com/105578152/180912092-37267c84-abd3-4f8d-9378-f50faedba667.png)

### 加密算法
![image](https://user-images.githubusercontent.com/105578152/180912198-eb606a0e-61b4-416a-b622-e20980a56d67.png)

### 解密算法
![image](https://user-images.githubusercontent.com/105578152/180912258-cd84b720-c088-4379-9856-330f67b682cf.png)

# 代码部分说明
## miracl库常用函数
### add
函数原型：void add(x,y,z)

功能：z=x+y

### big_to_bytes
函数原型：int big_to_bytes(max,x,ptr,justify)

功能：将正数x转换为二进制八位字符串

### bytes_to_big
函数原型：void bytes_to_big(len,ptr,x)

功能：将二进制八位字节字符串转换为大数字。二进制到大的转换。

### mirkill
函数原型：void mirkill(x)

功能： 释放内存大数所占的内存 清除MIRACL系统，释放所有内部变量。

### mirvar
函数原型：flash mirvar(iv)

功能：通过为big/flash变量保留适当数量的内存位置来初始化该变量。这个内存可以通过随后调用mirkill函数来释放。

### ecurve_init

函数原型： void ecurve_init(A,B,p,type)

功能：椭圆曲线方程初始化

### ecurve_mult

函数原型：void ecurve_mult(k,p,pa)

功能：点乘，pa=k*p

### epoint_init

函数原型：epoint* epoint_init()

功能：初始化点 返回epoint类型点

### epoint_free

函数原型：void epoint_free(p)

功能：释放点内存

### epoint_set

函数原型：BOOL epoint_set(x,y,lsb,p)

功能：设置点坐标
