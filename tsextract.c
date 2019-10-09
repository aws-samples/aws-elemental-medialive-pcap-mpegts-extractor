/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *   
 *     Licensed under the Apache License, Version 2.0 (the "License").
 *     You may not use this file except in compliance with the License.
 *     A copy of the License is located at
 *           
 *     http://www.apache.org/licenses/LICENSE-2.0
 *                   
 *     or in the "license" file accompanying this file. This file is distributed 
 *     on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either 
 *     express or implied. See the License for the specific language governing 
 *     permissions and limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC_NUMBER 0xa1b2c3d4

// See RFC-3550 for RTP header parsing details.
int GetRtpHeaderOffset(unsigned char* puHeader)
{
    unsigned int iSize = 12; // RTP_HEADER_SIZE
    iSize += 4 * (puHeader[0] & 0xf);
    if ( puHeader[0] & 0x10 )
    {    
        iSize += 4 + 4*((puHeader[iSize + 2] << 8) + puHeader[iSize + 3]);
    }
    return iSize;
}
void help()
{
    fprintf(stderr, "Usage: 1. If there is only one ts in the pcap:\n");
    fprintf(stderr, "\t\t ./tsextract < pcap file > ts file\n");
    fprintf(stderr, "Usage: 2. If there are more than one ts in the pcap:\n");
    fprintf(stderr, "\t\t ./tsextract destIP destPort < pcap file > ts file\n");
    fprintf(stderr, "Note: the < and > are required for file redirection\n");
}
int main(int argc, char **argv)
{
    /* File header variables */
    unsigned int magic;
    unsigned short major_v,minor_v;
    unsigned int timezoneOffset, timeStampAccuracy,snapshotLength;
    unsigned int linkLayerHeaderType;
    unsigned char dataBuf[2000];
    unsigned int ret;
    
    /* Per packet variables */
    unsigned int timeStampSeconds, timeStampMicroOrNano;
    unsigned int captureLength,captureLengthUntruncated;
    unsigned int frameCount=1;
    unsigned int offset,ipHdrOffset;
    unsigned char printOnce = 1;
    unsigned char dstIpAddr[15],specifiedIP[15];
    unsigned short dstUdpPort,specifiedUdpPort;
    unsigned char filterSpecified = 0;
    unsigned char *largePkt;
    
    
    if(argc > 1)
    {
        if((argc ==2) && ((!strcmp(argv[1],"-h") ||(!strcmp(argv[1], "--help")))))
        {
             help();
             return 0;
        }
        if(argc !=3) 
        {
            help();
            return 0;
        }
        strcpy(specifiedIP,argv[1]);
        specifiedUdpPort = atoi(argv[2]);
        filterSpecified = 1;
        
    }
    ret = fread(&magic,4,1,stdin);
    if(ret !=1)
    {
        //fprintf(stderr,"read failed %d\n", ret);
        return 0;
    }

    if(magic ==0x0A0D0D0A)
    {
        fprintf(stderr,"This looks like a pcap-ng file. Try tsextract-ng \n");
        return 0;
    }
    if(magic != MAGIC_NUMBER)
    {
        fprintf(stderr,"Only Little Endian captures supported\n");
        return 0;
    }
    
    ret = fread(&major_v,2,1,stdin);
    if(ret !=1)
    {
        // fprintf(stderr,"read failed %d\n", ret);
        return 0;
    }
    ret = fread(&minor_v,2,1,stdin);
    if(ret !=1)
    {
        // fprintf(stderr,"read failed\n");
        return 0;
    }
    ret = fread(&timezoneOffset,4,1,stdin);
    if(ret !=1)
    {
        // fprintf(stderr,"read failed\n");
        return 0;
    }
    ret = fread(&timeStampAccuracy,4,1,stdin);
    if(ret !=1)
    {
        // fprintf(stderr,"read failed\n");
        return 0;
    }
    ret = fread(&snapshotLength,4,1,stdin);
    if(ret !=1)
    {
        // fprintf(stderr,"read failed\n");
        return 0;
    }
    ret = fread(&linkLayerHeaderType,4,1,stdin);
    if(ret !=1)
    {
        // fprintf(stderr,"read failed\n");
        return 0;
    }
    
    fprintf(stderr, "Magic Number: 0x%x\n",magic);
    fprintf(stderr, "Major Version: 0x%x\n",major_v);
    fprintf(stderr, "Minor Version: 0x%x\n",minor_v);
    fprintf(stderr, "Time zone offset: 0x%x\n",timezoneOffset);
    fprintf(stderr, "Time Stamp Accuracy: 0x%x\n",timeStampAccuracy);
    fprintf(stderr, "Snapshot Length: 0x%x\n",snapshotLength);
    fprintf(stderr, "Link-layer header type: 0x%x\n",linkLayerHeaderType);
    
    if(linkLayerHeaderType != 1) // Ethernet only
    {
        fprintf(stderr,"Only Ethernet captures supported\n");
        return 0;
    }
    
    unsigned int packetCount = 0;
    while(!feof(stdin))
    {
        ret = fread(&timeStampSeconds,4,1,stdin);
        if(ret !=1)
        {
            //  fprintf(stderr,"read failed(EOF?) %d\n", ret);
            return 0;
        }
        ret = fread(&timeStampMicroOrNano,4,1,stdin);
        if(ret !=1)
        {
            //  fprintf(stderr,"read failed(EOF?) %d\n", ret);
            return 0;
        }
        ret = fread(&captureLength,4,1,stdin);
        if(ret !=1)
        {
            //  fprintf(stderr,"read failed(EOF?) %d\n", ret);
            return 0;
        }
        ret = fread(&captureLengthUntruncated,4,1,stdin);
        if(ret !=1)
        {
            //  fprintf(stderr,"read failed(EOF?) %d\n", ret);
            return 0;
        }
        unsigned char skip_packet = 0;
        if(captureLength > 2000)
        {
            fprintf(stderr,"capture Length appears too large for packet(%d) - %d - skipping\n",packetCount,captureLength);
            largePkt = (char *) malloc(captureLength);
            fread(largePkt,1,captureLength,stdin); // Toss the packet
            free(largePkt);
            skip_packet= 1;
        }
        
        if (!skip_packet)
        {
            ret = fread(dataBuf,1,captureLength,stdin);
            packetCount++;
            if(ret!=captureLength)
            {
                fprintf(stderr,"Incomplete frame - the end\n");
                return 0;
            }
        /* Check for ipv4 - First 12 bytes are src,dst MACs*/
            offset = 12;
            if(dataBuf[offset] != 0x08) /*EtherType 8 */
            {
                skip_packet = 1;
            }
            offset = 14; /*start of ip packet header */
            ipHdrOffset = 14; /*Save ip offset */
            sprintf(dstIpAddr,"%d.%d.%d.%d",dataBuf[ipHdrOffset+16],dataBuf[ipHdrOffset+17],dataBuf[ipHdrOffset+18],dataBuf[ipHdrOffset+19]);
            unsigned char type =dataBuf[offset] >> 4;
            unsigned char ipHdrLength = (dataBuf[offset] & 0xf) *4;
            unsigned char protocol = dataBuf[offset+9];
        
        
            if(type !=4)
            {
                skip_packet = 1;
            }
            if(protocol != 0x11) /*UDP */
            {
                //fprintf(stderr,"Protocol not UDP\n");
            
                skip_packet = 1;
            }
            if(!skip_packet)
            {
                offset = offset + ipHdrLength; /* fwd past iphdr */
                dstUdpPort = ((unsigned short)dataBuf[offset+2] << 8) | (unsigned short)dataBuf[offset+3];
                offset += 8; /* fwd past UDP header */
                unsigned int writeSize = captureLength - offset;
                //fprintf(stderr, "Size to write: %d\n", writeSize);
            
                unsigned int tsCheck = writeSize % 188;
                unsigned char skip_at_end = 0;
                if(tsCheck !=0) 
                {
                    int rtp_offset = GetRtpHeaderOffset(dataBuf+offset);
                    tsCheck = (writeSize - rtp_offset) % 188;
                    if (tsCheck != 0)
                    {
                        fprintf(stderr,"packet size error in packet(%d): %d - Maybe other than ts - skipping\n",packetCount, writeSize);
                        skip_at_end = 1;
                    }
                    else
                    {
                        offset += rtp_offset;
                        writeSize -= rtp_offset;
                    }
                }

                if(!skip_at_end)
                {
                    if(filterSpecified)
                    {
                    // If filters specified, only write the packets that match dest IP and UDP
                        if((specifiedUdpPort == dstUdpPort) && (!strcmp(specifiedIP,dstIpAddr)))
                        fwrite(&dataBuf[offset],1,writeSize,stdout);
                    }
                    else
                        fwrite(&dataBuf[offset],1,writeSize,stdout);
                }
                skip_at_end = 0;
            }
       }   
    }
    
    
}
