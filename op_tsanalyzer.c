/***
	Copyright 2015,  Rahul Raj Rajan (rahulraj.rajan@hotmail.com)
	See no evil, Hear no evil, Speak no evil!!
***/ 

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef FILE_BASED

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#endif

#define UDP_MAX_PKT_SIZE 	65535
#define TS_PKT_SIZE		188
#define APP_LAYER_HDR_SIZE 	12

uint64_t curPTS = -1;
uint64_t prevPTS;

double fCurPTS;
double fPrevPTS;

int pktCount = 0;

short pid;

int bytesRead = 0;

#ifndef FILE_BASED
struct udpSockReader
{
	struct sockaddr_in portal;
	int fd;
	unsigned char *pBuf;
	int bytes;
	int offset;
	FILE *dumpfp;
};
#endif

#ifdef FILE_BASED
	FILE *fp = NULL;
#else
	struct udpSockReader reader = {0};
#endif

static int read(unsigned char *apBuf, int anBytes)
{
#ifdef FILE_BASED
	return fread(apBuf, 1, anBytes, fp);
#else
	do{
		int ret = 0;
		int bytes = (reader.bytes - reader.offset);

		if(bytes >= anBytes)
		{
			memcpy(apBuf, (reader.pBuf + reader.offset), anBytes);
			reader.offset += anBytes;
			return anBytes;
		}
		else
		{
			if(bytes > 0)
				memmove(reader.pBuf, (reader.pBuf + reader.offset), bytes);

			reader.offset = bytes;
			reader.bytes = bytes;
		}

		ret = recv(reader.fd, (reader.pBuf + reader.offset), UDP_MAX_PKT_SIZE, 0);
		if(ret < 0)
		{
			return -1;
		}

		bytesRead = ret;

		if(reader.dumpfp)
		{
			fwrite((reader.pBuf + reader.offset + APP_LAYER_HDR_SIZE), 1, (ret - APP_LAYER_HDR_SIZE), reader.dumpfp);
			fflush(reader.dumpfp);
		}

		reader.bytes += ret;
		reader.offset = 0;

	}while(1);


#endif
}

static int parsePES(unsigned char *apBuf)
{
	uint64_t nPTS = 0;

	if(!apBuf)
		return -3;

	//printf("\n PES 0x%x 0x%x 0x%x \n", apBuf[0], apBuf[1], apBuf[2]);

	if((apBuf[0] != 0x00) || (apBuf[1] != 0x00) || (apBuf[2] != 0x01))
		return -4;

	{
		unsigned char *b = &apBuf[9];

		/** low 1 bit of b(5) **/
		nPTS = (((uint64_t)((b[0] & 0x08) >> 3)) << 32);
		/** high 2 bits of b(4) **/
		nPTS |= (((uint64_t)((b[0] & 0x06) >> 1)) << 30);
		/** low 6 Bits of b(4) **/
		nPTS |= (((uint64_t)((b[1] & 0xFC) >> 2)) << 24);
		/** high 2 Bits of b(3) **/
		nPTS |= (((uint64_t)((b[1] & 0x03))) << 22);
		/** low 6 Bits of b(3) **/
		nPTS |= (((uint64_t)((b[2] & 0xFC) >> 2)) << 16);
		/** high 1 Bit of b(2) **/
		nPTS |= (((uint64_t)((b[2] & 0x02) >> 1)) << 15);
		/** low 7 Bits of b(2) **/
		nPTS |= (((uint64_t)((b[3] & 0xFE) >> 1)) << 8);
		/** high 1 Bit of b(1) **/
		nPTS |= (((uint64_t)((b[3] & 0x01))) << 7);
		/** low 7 Bits of b(1) **/
		nPTS |= (((uint64_t)((b[4] & 0xFE)) >> 1));

		if(nPTS != curPTS)
		{
			//printf("\n%lld ->  %d", curPTS, pktCount);
			prevPTS = curPTS;
			curPTS = nPTS;
			//printf("\n PTS = %lf : PktCount : %d", fCurPTS, pktCount);
			fPrevPTS = fCurPTS;
			fCurPTS = (double)curPTS/(double)90;
			pktCount = 0;

			printf("\n Cur PTS = %lf, Diff = %lf\n", fCurPTS, (fCurPTS - fPrevPTS));
		}

		pktCount++;
	}

	return 0;
}

static int parseTS(unsigned char *apBuf, short *apCC)
{
	bool isPUSI = false;
	short nAF = 0, nAFLen = 0;
	short nPid = 0;

	if(!apBuf)
		return -1;

	if(apBuf[0] != 0x47)
		return -2;

	//printf("\n TS 0x%x 0x%x 0x%x 0x%x \n", apBuf[0], apBuf[1], apBuf[2], apBuf[3]);

	//printf("\n TS 0x%x 0x%x 0x%x 0x%x \n", apBuf[4], apBuf[5], apBuf[6], apBuf[7]);

	nPid = apBuf[2];
	nPid |= ((apBuf[1] & 0x1F) << 8);

	if(nPid != pid)
		return -5;

	isPUSI = ((apBuf[1] & 0x40) == 0x40) ? true : false;
	nAF = ((apBuf[3] & 0x30) >> 4);
	*apCC = (apBuf[3] & 0x0F);

	if(isPUSI)
	{
		if(nAF == 0x01)
			return parsePES(&apBuf[4]);
		else if(nAF = 0x11)
		{
			nAFLen = apBuf[4];
			//printf("\n AF = 0x%x Len = %d\n", nAF, nAFLen);
			return 	parsePES(&apBuf[5 + nAFLen]);
		}
	}

	pktCount++;

	return 0;
}

int main(int argc, char *argv[])
{
	unsigned char pBuf[376] = {0};
	short nCC = 0, nIndex = 0, nRet = 0, nPrevCC = 0;
	FILE *fp1 = NULL;

	if(argc < 3)
	{
		printf("\n <Exec> <InputFileName> <PID> \n");
		return -1;
	}

	fp1 = fopen("CC.txt", "w+");
	if(fp1 == NULL)
	{
		printf("\n Analysis File Open Error\n");
		return -1;
	}

#ifdef FILE_BASED
	fp = fopen(argv[1], "rb");
	if(fp == NULL)
	{
		printf("\n File Open Error \n");
		return -1;
	}
#else
	reader.pBuf = (unsigned char *)malloc(UDP_MAX_PKT_SIZE + TS_PKT_SIZE);
	if(!reader.pBuf)
	{
		printf("\n Buf Alloc Error \n");
		return -1;
	}

	reader.bytes = 0;
	reader.offset = 0;

	reader.dumpfp = fopen("test.ts", "wb");
	if(!reader.dumpfp)
	{
		printf("\n dump file open Error \n");
		goto RETURN;
	}


	reader.fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(reader.fd < 0)
	{
		printf("\n File Open Error \n");
		goto RETURN;
	}

	bzero(&reader.portal, sizeof(struct sockaddr_in));

	reader.portal.sin_port = htons(atoi(argv[1]));
	reader.portal.sin_addr.s_addr = htonl(INADDR_ANY);

	if(bind(reader.fd, (struct sockaddr *)&(reader.portal), sizeof(struct sockaddr_in)) < 0)
	{
		printf("\n File Bind Error \n");
		goto RETURN;
	}
#endif

	pid = atoi(argv[2]);

	while(1)
	{
		short expPkt = 0;

RELOOP:
		nIndex = 0;
		nRet = read(pBuf, 188);
		if(nRet != 188)
			goto RETURN;

		do{
			nRet = parseTS(pBuf + nIndex, &nCC);
			if(nRet == 0)
				break;
			else if(nRet == -2)
			{
				nRet = read(pBuf, 1);
				if(nRet != 1)
					goto RETURN;
				nIndex++;
			}
			else if(nRet == -5)
				goto RELOOP;
			else
			{
				printf("\n %d error\n", nRet);
				goto RETURN;
			}

		}while(1);

#ifndef FILE_BASED
		//printf("\n CC = %d\n", nCC);
		if(bytesRead)
		{
			//printf("\n[%ld] : %d bytes", curPTS, bytesRead);
			bytesRead = 0;
		}
#endif

		expPkt = ((nPrevCC + 1) % 16);

		if(nCC != expPkt)
		{
			//fprintf(fp1, "\n%ld %d -> %d\n", curPTS, ((nPrevCC + 1) % 16), (((nCC - 1) < 0) ? (16 + (nCC - 1)) : (nCC - 1)));

			short lastMissedPkt = (((nCC - 1) < 0) ? (16 + (nCC - 1)) : (nCC - 1));

			if(expPkt != lastMissedPkt)
				fprintf(fp1, "\n%lld %d -> %d", curPTS, expPkt, lastMissedPkt);
			else
				fprintf(fp1, "\n%lld %d", curPTS, expPkt);
			fflush(fp1);

		}

		nPrevCC = nCC;
	}
RETURN:
#ifdef FILE_BASED
	fclose(fp);
#else
	if(reader.dumpfp)
		fclose(reader.dumpfp);

	if(reader.fd)
		close(reader.fd);
	free(reader.pBuf);
#endif

	fclose(fp1);

	return 0;
}

