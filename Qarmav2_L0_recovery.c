#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>


int rho(unsigned char num) {
    return ((num << 1) | (num >> (3))) & 0x0F;
}

int s(int x) {
    int s_table[16] = {
       4, 7, 9, 11, 12, 6, 14, 15, 0, 5, 1, 13, 8, 3, 2, 10
    };

    
    return s_table[x];
}


int main() {
    
    printf(" Program for the key recovery");
    int c0=7,c1=11,c2=9,c3=13,c4=15,c5=9,c6=15,c7=3,c8=15,c9=0,c10=15,c11=4,c12=7,c13=3,c14=14,c15=12;
    int p0=1,p1=13,p2=9,p3=2,p4=6,p5=0,p6=0,p7=3,p8=15,p9=0,p10=15,p11=4,p12=8,p13=3,p14=13,p15=0;
    int u0=3,u1=4,u2=2,u3=5,u4=6,u5=0,u6=2,u7=13,u8=11,u9=11,u10=0,u11=1,u12=3,u13=11,u14=9,u15=10;
    int v0=4,v1=4,v2=3,v3=13,v4=8,v5=7,v6=0,v7=12,v8=1,v9=2,v10=1,v11=1,v12=4,v13=3,v14=4,v15=4;
    int q0=15,q1=10,q4=11,q5=11,q14=6,q15=13;
    int x0=10,x1=8,x2=10,x3=14,x4=13,x5=11,x6=12,x7=0,x8=4,x9=12,x10=8,x11=8,x12=9,x13=15,x14=8,x15=4;

 int k0,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15, a1,a2,a3,b1,b2,b3;

long long int cnt=0, total=0;
for (k0 = 0; k0 < 16; k0++) 
    for (k1 = 0; k1 < 16; k1++) 
        for (k4 = 0; k4 < 16; k4++) 
            for (k5 = 0; k5 < 16; k5++) 
                for (k10 = 0; k10 < 16; k10++) 
                    for (k11 = 0; k11 < 16; k11++) 
                        for (k14 = 0; k14 < 16; k14++)  
                             for (k15 = 0; k15 < 16; k15++){
                                 total++;


/*rho^2(p_1')=p_3'......with fault 0101*/                                 
a1=rho(c5 ^ k5);    a2=rho(rho(c15 ^ k15));     a3=rho(rho(rho(c0 ^ k0)));
b1=rho(p5 ^ k5);    b2=rho(rho(p15 ^ k15));     b3=rho(rho(rho(p0 ^ k0)));
int left_side1 = rho(rho(s(a1^a2^a3)^ s(b1^b2^b3)));

a1=rho(c1 ^ k1);    a2=rho(rho(c14 ^ k14));     a3=rho(rho(rho(c4 ^ k4)));
b1=rho(p1 ^ k1);    b2=rho(rho(p14 ^ k14));     b3=rho(rho(rho(p4 ^ k4)));
int right_side1 = (s(a1^a2^a3)^ s(b1^b2^b3));

/*rho^2(p_1')=p_3'......with fault 1100*/ 

a1=rho(c5 ^ k5);    a2=rho(rho(c15 ^ k15));     a3=rho(rho(rho(c0 ^ k0)));
b1=rho(q5 ^ k5);    b2=rho(rho(q15 ^ k15));     b3=rho(rho(rho(q0 ^ k0)));
int left_side11 = rho(rho(s(a1^a2^a3)^ s(b1^b2^b3)));

a1=rho(c1 ^ k1);    a2=rho(rho(c14 ^ k14));     a3=rho(rho(rho(c4 ^ k4)));
b1=rho(q1 ^ k1);    b2=rho(rho(q14 ^ k14));     b3=rho(rho(rho(q4 ^ k4)));
int right_side11 = (s(a1^a2^a3)^ s(b1^b2^b3));

/*rho^2(DeltaU_8^(r-1))=Delta_13^(r-1)......for fault 1110*/
a1=rho(u15 ^ k15);    a2=rho(rho(u0 ^ k0));     a3=rho(rho(rho(u10 ^ k10)));
b1=rho(v15 ^ k15);    b2=rho(rho(v0 ^ k0));     b3=rho(rho(rho(v10 ^ k10)));
int left_side2 = rho(rho(s(a1^a2^a3)^ s(b1^b2^b3)));

a1=rho(u11 ^ k11);    a2=rho(rho(u1 ^ k1));     a3=rho(rho(rho(u14 ^ k14)));
b1=rho(v11 ^ k11);    b2=rho(rho(v1 ^ k1));     b3=rho(rho(rho(v14 ^ k14)));
int right_side2 = (s(a1^a2^a3)^ s(b1^b2^b3));


/*rho^2(DeltaU_8^(r-1))=Delta_13^(r-1)......for fault 0011*/
a1=rho(u15 ^ k15);    a2=rho(rho(u0 ^ k0));     a3=rho(rho(rho(u10 ^ k10)));
b1=rho(x15 ^ k15);    b2=rho(rho(x0 ^ k0));     b3=rho(rho(rho(x10 ^ k10)));
int left_side22 = rho(rho(s(a1^a2^a3)^ s(b1^b2^b3)));

a1=rho(u11 ^ k11);    a2=rho(rho(u1 ^ k1));     a3=rho(rho(rho(u14 ^ k14)));
b1=rho(x11 ^ k11);    b2=rho(rho(x1 ^ k1));     b3=rho(rho(rho(x14 ^ k14)));
int right_side22 = (s(a1^a2^a3)^ s(b1^b2^b3));
           
/*rho^2(DeltaU_12^(r-1))=Delta_9^(r-1)......for fault 1110*/
a1=rho(u0 ^ k0);    a2=rho(rho(u10 ^ k10));     a3=rho(rho(rho(u5 ^ k5)));
b1=rho(v0 ^ k0);    b2=rho(rho(v10 ^ k10));     b3=rho(rho(rho(v5 ^ k5)));
int left_side3 = rho(rho(s(a1^a2^a3)^ s(b1^b2^b3)));

a1=rho(u4 ^ k4);    a2=rho(rho(u11 ^ k11));     a3=rho(rho(rho(u1 ^ k1)));
b1=rho(v4 ^ k4);    b2=rho(rho(v11 ^ k11));     b3=rho(rho(rho(v1 ^ k1)));
int right_side3 = (s(a1^a2^a3)^ s(b1^b2^b3));

/*rho^2(DeltaU_12^(r-1))=Delta_9^(r-1)......for fault 0011*/
a1=rho(u0 ^ k0);    a2=rho(rho(u10 ^ k10));     a3=rho(rho(rho(u5 ^ k5)));
b1=rho(x0 ^ k0);    b2=rho(rho(x10 ^ k10));     b3=rho(rho(rho(x5 ^ k5)));
int left_side33 = rho(rho(s(a1^a2^a3)^ s(b1^b2^b3)));

a1=rho(u4 ^ k4);    a2=rho(rho(u11 ^ k11));     a3=rho(rho(rho(u1 ^ k1)));
b1=rho(x4 ^ k4);    b2=rho(rho(x11 ^ k11));     b3=rho(rho(rho(x1 ^ k1)));
int right_side33 = (s(a1^a2^a3)^ s(b1^b2^b3));






//printf("%d\n", left_side2 );

                  

if((left_side1 == right_side1) && (left_side2 == right_side2 ) && (left_side3 == right_side3) && (left_side11 == right_side11) && (left_side22 == right_side22 ) && (left_side33 == right_side33))
{

  cnt++;
  if(cnt%10==0)
     printf("%lld   %lld   %0.8f  \n", total, cnt, log2((double)cnt/total));

 }
    

}

//printf("%lld\n", cnt);
}
