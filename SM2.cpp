#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <malloc.h>
#include <time.h>
#include <string>
#include "SM3.h"
typedef unsigned char uc;
#define SEED 0x1BD8C95A

extern "C"
{
#include "miracl.h"
#include "mirdef.h"
}
#pragma comment(lib,"miracl.lib")

//�ο����ף�CSDN��SM2 ��Բ���߹�Կ�����㷨
//miracl�ⳣ�ú���
//mivar(iv)->int iv ��ʼ��
//big x;mirkill(x)->�ͷŴ���
//cotnum(n, stdout)->��ӡn
//cinnum(n, stdin)->����n
//cinstr()�������ַ���ת���ɴ���


void print_buf(uc* buf, int len)
{
	for (int i = 0; i < len; i++)
	{
		if (i % 32 != 31)
			printf("%02x", buf[i]);
		else
			printf("%02x\n", buf[i]);
	}
	return;
}

struct curve
{
	char *p, * a, * b, * n, * x, * y;
};

struct curve  _init_value= 
{ 
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
	"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
	"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
	"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
};

//���ɽ��շ��Ĺ�˽Կ��
void keygen(uc* X, int* lx, uc* Y, int* ly, uc* sk, int* lsk)
{
	struct curve* s = &_init_value;
	epoint* g, * pk;
	big a, b, p, n, x, y, k;
	miracl* mip = mirsys(20, 0);//��ʼ��miraclϵͳ
	mip->IOBASE = 16;//����Ϊ16����

	//��ʼ��
	p = mirvar(0);
	a = mirvar(0);
	b = mirvar(0);
	n = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	k = mirvar(0);

	//��16�����ַ���ת����big����
	cinstr(p, s->p);
	cinstr(a, s->a);
	cinstr(b, s->b);
	cinstr(n, s->n);
	cinstr(x, s->x);
	cinstr(y, s->y);

	//��ʼ����Բ����
	ecurve_init(a, b, p, MR_PROJECTIVE);
	g = epoint_init();//��ʼ��Ϊ����Զ��
	pk = epoint_init();
	epoint_set(x, y, 0, g);//���õ����� g=(x,y)

	//����˽Կ
	irand(time(NULL) + SEED);//��ʼ������
	bigrand(n, k);
	ecurve_mult(k, g, pk);//��ˣ�t=k*g
	epoint_get(pk, x, y);

	//д�빫Կ
	*lx = big_to_bytes(0, x, (char*)X, FALSE);
	*ly = big_to_bytes(0, y, (char*)Y, FALSE);
	*lsk = big_to_bytes(0, k, (char*)sk, FALSE);

	//�ͷ��ڴ�
	mirkill(p);
	mirkill(a);
	mirkill(b);
	mirkill(n);
	mirkill(x);
	mirkill(y);
	mirkill(k);
	epoint_free(g);//�ͷŵ��ڴ�
	epoint_free(pk);
	mirexit();
}

int KDF(uc* x, uc* y, int l, uc* keybuf)
{
	uc buf[70];
	uc abs[32];
	unsigned int tmp = 0x00000001;
	uc* p;
	p = keybuf;

	//����buffer
	memcpy(buf, x, 32);
	memcpy(buf + 32, y, 32);

	for (int i = 0; i < l / 32; i++)
	{
		buf[64] = (tmp >> 24) & 0xFF;
		buf[65] = (tmp >> 16) & 0xFF;
		buf[66] = (tmp >> 8) & 0xFF;
		buf[67] = tmp & 0xFF;
		sm3(buf, 68, p);
		p += 32;
		tmp++;
	}
	if (l % 32 != 0)
	{
		buf[64] = (tmp >> 24) & 0xFF;
		buf[65] = (tmp >> 16) & 0xFF;
		buf[66] = (tmp >> 8) & 0xFF;
		buf[67] = tmp & 0xFF;
		sm3(buf, 68, abs);
	}
	memcpy(p, abs, l % 32);

	int i;
	for (i = 0; i < l; i++)
	{
		if (keybuf[i] != 0)
			break;
	}

	if (i < l)
		return 1;
	else
		return 0;

}

int SM2_enc(uc* plaintext, int lp, uc* X, int lx, uc* Y, int ly, uc* ciphertext)
{
	struct curve* s = &_init_value;
	big x1, x2, y1, y2, k;
	big a, b, p, n, x, y;
	epoint* g, * t, * c, * p1, * kp1;
	int res = -1;
	uc tl[32], tr[32];
	uc* tmp;
	tmp = (uc*)malloc(lp + 64);
	if (tmp == NULL)
		return -1;
	miracl* mip = mirsys(20, 0);//��ʼ��miraclϵͳ
	mip->IOBASE = 16;

	//��ʼ��
	p = mirvar(0);
	a = mirvar(0);
	b = mirvar(0);
	n = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	k = mirvar(0);
	x1 = mirvar(0);
	x2 = mirvar(0);
	y1 = mirvar(0);
	y2 = mirvar(0);

	//�������ַ�����Ϊ����
	cinstr(p, s->p);
	cinstr(a, s->a);
	cinstr(b, s->b);
	cinstr(n, s->n);
	cinstr(x, s->x);
	cinstr(y, s->y);

	//��ʼ����Բ����
	ecurve_init(a, b, p, MR_PROJECTIVE);
	g = epoint_init();//��ʼ��Ϊ����Զ��
	t = epoint_init();
	c = epoint_init();
	p1 = epoint_init();
	kp1 = epoint_init();
	epoint_set(x, y, 0, g);

	//����ԿX,Y��ֵ��x,y
	bytes_to_big(lx, (char*)X, x);
	bytes_to_big(ly, (char*)Y, y);
	epoint_set(x, y, 0, t);

	//ѡȡ�����k
	irand(time(NULL) + SEED);
another_loop:
	do
	{
		bigrand(n, k);
	} while (k->len == 0);

	ecurve_mult(k, g, c);//��ˣ�c=k*g
	epoint_get(c, x1, y1);
	big_to_bytes(32, x1, (char*)ciphertext, TRUE);
	big_to_bytes(32, y1, (char*)ciphertext + 32, TRUE);

	if (point_at_infinity(p1))
		goto exit_enc;

	ecurve_mult(k, p1, kp1);//kp1=k*p1
	epoint_get(kp1, x2, y2);//��kp1�õ�x2,y2
	big_to_bytes(32, x2, (char*)tl, TRUE); 
	big_to_bytes(32, y2, (char*)tr, TRUE);

	if (KDF(tl, tr, lp, ciphertext + 64) == 0)
		goto another_loop;

	for (int i = 0; i < lp; i++)
		ciphertext[64 + i] ^= plaintext[i];

	memcpy(tmp, tl, 32);
	memcpy(tmp + 32, plaintext, lp);
	memcpy(tmp + 32 + lp, tr, 32);

	sm3(tmp, 64 + lp, &ciphertext[64 + lp]);
	res = lp + 64 + 32;

exit_enc: 
	mirkill(k);
	mirkill(a);
	mirkill(b);
	mirkill(p);
	mirkill(n);
	mirkill(x);
	mirkill(y);
	mirkill(x1);
	mirkill(x2);
	mirkill(y1);
	mirkill(y2);
	epoint_free(g);   //�ͷŵ��ڴ�
	epoint_free(t);
	epoint_free(p1);
	epoint_free(kp1);
	mirexit();
	free(tmp);
	return res;
}

int SM2_dec(uc* ciphertext, int lp, uc* sk, int lsk, uc* plaintext)
{
	struct curve* s = &_init_value;
	big a, b, p, n, x, y, k, c, d;
	big x1, y1, k1;
	epoint* g, * c1, * dc1;
	uc c2[32];
	uc tl[32], tr[32];
	int res = -1;
	uc* tmp;
	tmp = (uc*)malloc(lp + 64);
	if (tmp == NULL)
		return 0;
	if (lp < 96)
		return 0;
	lp -= 96;
	miracl* mip = mirsys(20, 0);//��ʼ��miraclϵͳ
	mip->IOBASE = 16;

	
	a = mirvar(0);
	b = mirvar(0);
	p = mirvar(0);
	n = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	k = mirvar(0);
	d = mirvar(0);
	c = mirvar(0);
	k1= mirvar(0);
	x1 = mirvar(0);
	y1 = mirvar(0);
	bytes_to_big(lsk, (char*)sk, d);
	
	cinstr(p, s->p);
	cinstr(a, s->a);
	cinstr(b, s->b);
	cinstr(n, s->n);
	cinstr(x, s->x);
	cinstr(y, s->y);

	ecurve_init(a, b, p, MR_PROJECTIVE);
	g = epoint_init();//��ʼ��Ϊ����Զ��
	c1 = epoint_init();
	dc1 = epoint_init();
	bytes_to_big(32, (char*)ciphertext, x);  
	bytes_to_big(32, (char*)ciphertext + 32, y);

	if (!epoint_set(x, y, 0, c1))//��ʼ���㲻����Բ�����ϣ��˳�
		goto exit_dec;
	if (point_at_infinity(c1))//����Զ���˳�
		goto exit_dec;

	ecurve_mult(d, c1, dc1);
	epoint_get(dc1, x1, y1);

	big_to_bytes(32, x1, (char*)tl, TRUE);
	big_to_bytes(32, y1, (char*)tr, TRUE);
	if (KDF(tl, tr, lp, plaintext) == 0)
		goto exit_dec;

	for (int i = 0; i < lp; i++)
		plaintext[i] ^= ciphertext[i + 64];

	memcpy(tmp, tl, 32);
	memcpy(tmp + 32, plaintext, lp);
	memcpy(tmp + 32 + lp, tr, 32);
	sm3(tmp, 64 + lp, c2);
	if (memcmp(c2, ciphertext + 64 + lp, 32) != 0)
		goto exit_dec;
	res = lp;

exit_dec:
	mirkill(c);
	mirkill(k);
	mirkill(p);
	mirkill(a);
	mirkill(b);
	mirkill(n);
	mirkill(x);
	mirkill(y);
	mirkill(k1);
	mirkill(d);
	mirkill(x1);
	mirkill(y1);
	epoint_free(g);
	epoint_free(dc1);
	mirexit();
	free(tmp);

	return res;
}

int main()
{
	uc d[32];
	uc x[32];
	uc y[32];
	uc c[256];
	uc M[256];
	uc m[256] = "123456789ABCDEFFEDCBA987654321";
	int lm = strlen((const char*)m);
	int lx, ly, ld;

	keygen(x, &lx, y, &ly, d, &ld);
	SM2_enc(m, lm, x, 32, y, 32, c);
	printf("Ciphertext:\n");
	print_buf(c, 64 + lm + 32);

	return 0;
}