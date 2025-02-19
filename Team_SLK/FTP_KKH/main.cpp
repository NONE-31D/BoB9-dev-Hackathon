#if !defined(WIN32) && !defined(WINx64)

#include <in.h> 

#endif
#include <iostream>
#include "stdlib.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"
#include "RawPacket.h"
#include <bits/stdc++.h>
#include "json/json.h"

using namespace std;

vector<pair<int, string>> FTP_LOG;
queue<pair<string, string>> FTP_QUEUE;
int ftp_response_code;
string ftp_response_arg, ftp_request_cmd, ftp_request_arg;

Json::Value root;

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType) {
   switch (protocolType) {
      case pcpp::Ethernet:
      return "Ethernet";

      case pcpp::IPv4:
      return "IPv4";

      case pcpp::TCP:
      return "TCP";

      case pcpp::HTTPRequest:
      case pcpp::HTTPResponse:
      return "HTTP";

      default:
      return "Unknown";
   }
}

std::string printTcpFlags(pcpp::TcpLayer* tcpLayer) {
   std::string result = "";

   if (tcpLayer->getTcpHeader()->synFlag == 1) result += "SYN ";

   if (tcpLayer->getTcpHeader()->ackFlag == 1) result += "ACK ";

   if (tcpLayer->getTcpHeader()->pshFlag == 1) result += "PSH ";

   if (tcpLayer->getTcpHeader()->cwrFlag == 1) result += "CWR ";

   if (tcpLayer->getTcpHeader()->urgFlag == 1) result += "URG ";

   if (tcpLayer->getTcpHeader()->eceFlag == 1) result += "ECE ";

   if (tcpLayer->getTcpHeader()->rstFlag == 1) result += "RST ";

   if (tcpLayer->getTcpHeader()->finFlag == 1) result += "FIN ";

   return result;
}

std::string printTcpOptionType(pcpp::TcpOptionType optionType) {
   switch (optionType) {
   case pcpp::PCPP_TCPOPT_NOP:
   return "NOP";

   case pcpp::PCPP_TCPOPT_TIMESTAMP:
   return "Timestamp";

   default:
   return "Other";
   }
}

std::string printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod) {
   switch (httpMethod) {
   case pcpp::HttpRequestLayer::HttpGET:
   return "GET";

   case pcpp::HttpRequestLayer::HttpPOST:
   return "POST";

   default:
   return "Other";
   }
}

uint8_t my_ntohs(uint8_t n) {
   return (n & 0xf0) >> 4 | (n & 0x0f) << 4;
}

u_char ftp_data[1111111];
u_char smtp_data[1111111];
int smtp_data_flag;
unsigned int ftp_data_size, ftp_data_idx, smtp_data_idx;

int main(int argc, char* argv[]) {

   char* filename = argv[1];

   // use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
   // and create an interface instance that both readers implement
   pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(filename);

   // verify that a reader interface was indeed created
   if (reader == NULL) {
      printf("Cannot determine reader for file type\n");
      exit(1);
   }

   // open the reader for reading
   if (!reader->open()) {
      printf("Cannot open input.pcap for reading\n");
      exit(1);
   }

   unsigned int ftp_data_port = 0;
   unsigned int packet_num = 1;

   // 여기서부터 패킷 반복적으로 읽어오기...
   while(1) {
      pcpp::RawPacket rawPacket;

      if (!reader->getNextPacket(rawPacket)) {
         break;
      }

      // parse the raw packet
      pcpp::Packet parsedPacket(&rawPacket);

      //About Each Layer : type, total length, header length, payload length
      printf("\n\n=========================================================================================================\n");
      printf("%d번째 패킷\n", packet_num++);
      int is_tcp =0;
      int payload_length =0;
      int total_length =0;

      for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer()) {
         is_tcp++;
         if (is_tcp == 1) total_length = (int)curLayer->getDataLen();
         if (is_tcp == 4) payload_length = (int)curLayer->getDataLen();

         printf("Layer type: %s; Total data: %d [bytes]; Layer data: %d [bytes]; Layer payload: %d [bytes]\n",
         getProtocolTypeAsString(curLayer->getProtocol()).c_str(), // get layer type
         (int)curLayer->getDataLen(), // get total length of the layer
         (int)curLayer->getHeaderLen(), // get the header length of the layer
         (int)curLayer->getLayerPayloadSize()); // get the payload length of the layer (equals total length minus header length)
      }

      //****************Ethernet layer*****************
      pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();

      if (ethernetLayer == NULL) {
         printf("Something went wrong, couldn't find Ethernet layer\n");
         continue;
      }

      // print the source and dest MAC addresses and the Ether type
      printf("\nSource MAC address: %s\n", ethernetLayer->getSourceMac().toString().c_str());
      printf("Destination MAC address: %s\n", ethernetLayer->getDestMac().toString().c_str());
      printf("Ether type = 0x%X\n", ntohs(ethernetLayer->getEthHeader()->etherType));


      //****************IPv4 layer*****************
      pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

      if (ipLayer == NULL) {
         printf("Couldn't find IPv4 layer\n");
         continue;
      }

      // print source and dest IP addresses, IP ID and TTL
      printf("\nSource IP address: %s\n", ipLayer->getSrcIpAddress().toString().c_str());
      printf("Destination IP address: %s\n", ipLayer->getDstIpAddress().toString().c_str());
      printf("IP ID: 0x%X\n", ntohs(ipLayer->getIPv4Header()->ipId));
      printf("TTL: %d\n", ipLayer->getIPv4Header()->timeToLive);


      //****************TCP layer*****************
      pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();

      if (tcpLayer == NULL) {
         printf("Couldn't find TCP layer\n");
         continue;
      }

      // printf TCP source and dest ports, window size, and the TCP flags 
      printf("\nSource TCP port: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->portSrc));
      int src_port = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);

      printf("Destination TCP port: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->portDst));
      int dst_port = (int)ntohs(tcpLayer->getTcpHeader()->portDst);

      printf("Window size: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->windowSize));
      printf("TCP flags: %s\n", printTcpFlags(tcpLayer).c_str());
      printf("TCP Sequence Number : %lu\n", ntohl(tcpLayer->getTcpHeader()->sequenceNumber));
      printf("TCP Ack Number : %lu\n", ntohl(tcpLayer->getTcpHeader()->ackNumber));

      // go over all TCP options in this layer and print its type
      printf("TCP options: ");
      for (pcpp::TcpOption tcpOption = tcpLayer->getFirstTcpOption(); tcpOption.isNotNull(); tcpOption = tcpLayer->getNextTcpOption(tcpOption))
         printf("%s ", printTcpOptionType(tcpOption.getTcpOptionType()).c_str());
         printf("\n");


      //*************** HTTP ? SMTP ? FTP ? *****************
      pcpp::HttpRequestLayer* httpRequestLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();

      int payload_start = total_length - payload_length;

      if(is_tcp == 4) {
         if (httpRequestLayer == NULL) {
            /*
            if((src_port == 25)||(src_port == 465)||(src_port == 587)||(src_port == 2525)||
            (dst_port == 25)||(dst_port == 465)||(dst_port == 587)||(dst_port == 2525)) {
            */
            if ((src_port == 587 || src_port == 3326) && (dst_port == 587 || dst_port == 3326)) { // SMTP 패킷이라면...
               printf("\n[ SMTP Packet ]\n");

               const u_char* packet;
               packet = (u_char*) rawPacket.getRawData();
               string smtp_response_code = "";
               if (src_port == 587) { // server -> client
                  printf("(server) -> (client)\n");
                  for (int i = payload_start; i < payload_start + 3; i++) {
                     smtp_response_code += packet[i];
                  }
                  cout << "smtp response code : " << smtp_response_code << '\n';
                  if (smtp_response_code == "354") {
                     smtp_data_flag = 1;
                  }
                  if (smtp_data_flag && smtp_response_code == "250") {
                     smtp_data_flag = 0;
                     for (int i = 0; i < smtp_data_idx; i++) {
                        printf("%c" , smtp_data[i]);
                     }
                  }
               } else if (dst_port == 587) { // client -> server
                  printf("(client) -> (server)\n");
                  if (smtp_data_flag) {
                     for (int i = payload_start; i < total_length; i++) {
                        smtp_data[smtp_data_idx++] = packet[i];
                     }
                  }
               }

               string response_code = "";
               printf("Response : ");
               for(int i = payload_start; i<total_length; i++) {
                  printf("%c", packet[i]);
               }
               printf("\n");

            } else if (src_port == 21) { // FTP Response 패킷이라면...
               printf("\n[ FTP Response Packet ]\n");
               const uint8_t* packet = rawPacket.getRawData();

               uint16_t start = 14 + 20 + my_ntohs(packet[46]) * 4;
               uint16_t TOTAL_LENGTH = ntohs(ipLayer->getIPv4Header()->totalLength) + 14;

               printf("TCP header len is %d\n", my_ntohs(packet[46]) * 4);
               printf("start index is %d\n", start);
               printf("total length is %d\n", TOTAL_LENGTH);
               printf("\nResponse: ");

               for (int i = payload_start; i<total_length; i++) {
                  printf("%c", packet[i]);
               }

               std::string ftp_command = "";
            
               printf("\nResponse Code : ");
               for (int i = start; i < start + 3; i++) {
                  ftp_command += (u_char) packet[i];
               }
               ftp_response_code = atoi(ftp_command.c_str());
               printf("%d", ftp_response_code);

               ftp_command = "";
            
               printf("\nResponse Arg : ");
               for (int i = start + 4; i < TOTAL_LENGTH; i++) {
                  if (packet[i] == 0x0d) break; // \r을 만나면 바로 종료... 끝이니까...
                  ftp_command += (u_char) packet[i];
                  printf("%c", packet[i]);
               }
               printf("\n");
               
               ftp_response_arg = ftp_command;
               std::cout << ftp_response_arg << '\n';
               
               FTP_LOG.push_back({ ftp_response_code, ftp_response_arg });
               
               if (ftp_response_code == 227) { // passive mode
                  ftp_data_port = 0;
                  std::string port_temp = "";
                  for (int i = 23; i < ftp_command.length(); i++) {
                     if (ftp_command[i] == ')') break;
                     port_temp += ftp_command[i];
                  }
                  char* num_arr = new char[1000];
                  strcpy(num_arr, port_temp.c_str());

                  char* tok = strtok(num_arr, ",");
                  int cnt = 0;
                  while (tok != NULL) {
                     cnt++;
                     if (cnt == 5) {
                        ftp_data_port += atoi(tok) * 256;
                     } else if (cnt == 6) {
                        ftp_data_port += atoi(tok);
                     }
                     tok = strtok(NULL, ",");
                  }
               }
               if (ftp_response_code == 226) { // 파일 전송 등이 완료된 코드
                  if (ftp_data_size == 0) continue;
                  printf("ftp data size : %d\n", ftp_data_size);
                  
                  // 데이터 hex값 출력하는 부분
                  /*
                  for (int i = 0; i < ftp_data_size; i++) {
                     printf("%.2x ", ftp_data[i]);
                  }
                  */
               
                  // 여기서 파일 저장함...
                  // 파일 확장자별로 분리해서 저장하자...
                  ofstream myfile;
                  myfile.open(ftp_request_arg, ios::binary);
                  myfile.write((const char*) ftp_data, ftp_data_size);
                  myfile.close();
                  memset(ftp_data, 0, sizeof(ftp_data));
                  ftp_data_size = ftp_data_idx = 0;
               }
               printf("ftp_data_port : %d\n", ftp_data_port);


               Json::Value temp;
               temp["Source Mac"] = ethernetLayer->getSourceMac().toString();
               temp["Destination Mac"] = ethernetLayer->getDestMac().toString();
               temp["Source Ip"] = ipLayer->getSrcIpAddress().toString();
               temp["Destination Ip"] = ipLayer->getDstIpAddress().toString();
               temp["Source TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
               temp["Destination TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
               temp["Protocol"] = "FTP";
               temp["Response code"] = ftp_response_code;
               temp["Response arg"] = ftp_response_arg;

               root.append(temp);

            } else if (dst_port == 21) { // FTP Request 패킷이라면...
               printf("\n[ FTP Request Packet ]\n");
               const uint8_t* packet = rawPacket.getRawData();

               uint16_t start = 14 + 20 + my_ntohs(packet[46]) * 4;
               uint16_t TOTAL_LENGTH = ntohs(ipLayer->getIPv4Header()->totalLength) + 14;

               std::string ftp_command = "";

               printf("TCP header len is %d\n", my_ntohs(packet[46]) * 4);
               printf("start index is %d\n", start);
               printf("total length is %d\n", TOTAL_LENGTH);
               printf("\nRequest: ");

               for (int i = payload_start; i<total_length; i++) {
                  printf("%c", packet[i]);
               }
               int cmd_flag = 0;
               printf("\nResponse Arg : ");
               for (int i = start; i < TOTAL_LENGTH; i++) {
                  if (packet[i] == ' ') {
                     ftp_request_cmd = ftp_command;
                     ftp_command = "";
                     cmd_flag = 1;
                     continue;
                  }
                  if (packet[i] == 0x0d) break; // \r을 만나면 바로 종료... 끝이니까...
                  ftp_command += (u_char) packet[i];
                  printf("%c", packet[i]);
               }
               printf("\n");
               std::cout << ftp_command << '\n';
               if (cmd_flag == 1) { // 인자가 2개일 경우...
                  ftp_request_arg = ftp_command;
                  FTP_QUEUE.push({ ftp_request_cmd, ftp_command });
                  FTP_LOG.push_back({ 1, ftp_request_cmd + " " + ftp_command });
               } else {
                  ftp_request_cmd = ftp_command;
                  ftp_request_arg = "";
                  FTP_QUEUE.push({ ftp_request_cmd, ftp_request_arg });
                  FTP_LOG.push_back({ 1, ftp_command });
               }

               Json::Value temp;
               temp["Source Mac"] = ethernetLayer->getSourceMac().toString();
               temp["Destination Mac"] = ethernetLayer->getDestMac().toString();
               temp["Source Ip"] = ipLayer->getSrcIpAddress().toString();
               temp["Destination Ip"] = ipLayer->getDstIpAddress().toString();
               temp["Source TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
               temp["Destination TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
               temp["Protocol"] = "FTP";
               temp["Request cmd"] = ftp_request_cmd;
               temp["Request arg"] = ftp_response_arg;

               root.append(temp);

            } else if (src_port == ftp_data_port) { // 받는 FTP-DATA 패킷이라면...

               FTP_LOG.push_back({ 2, ftp_request_cmd + " " + ftp_request_arg });

               Json::Value temp;
               temp["Source Mac"] = ethernetLayer->getSourceMac().toString();
               temp["Destination Mac"] = ethernetLayer->getDestMac().toString();
               temp["Source Ip"] = ipLayer->getSrcIpAddress().toString();
               temp["Destination Ip"] = ipLayer->getDstIpAddress().toString();
               temp["Source TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
               temp["Destination TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
               temp["Protocol"] = "FTP-DATA";

               root.append(temp);

               if (ftp_request_cmd != "RETR") continue;

               printf("\n[ FTP DATA Packet ] : 받는\n");

               const uint8_t* packet = rawPacket.getRawData();

               uint16_t start = 14 + 20 + my_ntohs(packet[46]) * 4;

               printf("start index is %d\n", start);
               printf("total length is %d\n", total_length);

               for (int i = start; i < total_length; i++) {
                  ftp_data[ftp_data_idx++] = packet[i];
               }
               ftp_data_size += total_length - start;

            } else if (dst_port == ftp_data_port) { // 보내는. 업로드하는 FTP-DATA 패킷이라면...

               FTP_LOG.push_back({ 3, ftp_request_cmd + " " + ftp_request_arg });
               
               Json::Value temp;
               temp["Source Mac"] = ethernetLayer->getSourceMac().toString();
               temp["Destination Mac"] = ethernetLayer->getDestMac().toString();
               temp["Source Ip"] = ipLayer->getSrcIpAddress().toString();
               temp["Destination Ip"] = ipLayer->getDstIpAddress().toString();
               temp["Source TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
               temp["Destination TCP Port"] = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
               temp["Protocol"] = "FTP-DATA";

               root.append(temp);

               if (ftp_request_cmd != "STOR") continue;
               printf("\n[ FTP DATA Packet ] : 보내는\n");

               const uint8_t* packet = rawPacket.getRawData();

               uint16_t start = 14 + 20 + my_ntohs(packet[46]) * 4;

               printf("start index is %d\n", start);
               printf("total length is %d\n", total_length);

               for (int i = start; i < total_length; i++) {
                  ftp_data[ftp_data_idx++] = packet[i];
               }
               ftp_data_size += total_length - start;
            }
         }
      }
      // If It's HTTP Packet Print method, URI, host, user-agent ...
      if (httpRequestLayer != NULL) {
         printf("\n[ HTTP Packet ]\n");
         printf("\nHTTP method: %s\n", printHttpMethod(httpRequestLayer->getFirstLine()->getMethod()).c_str());
         printf("HTTP URI: %s\n", httpRequestLayer->getFirstLine()->getUri().c_str());
         printf("HTTP host: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue().c_str());
         printf("HTTP user-agent: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD)->getFieldValue().c_str());
         printf("HTTP cookie: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD)->getFieldValue().c_str());
         printf("HTTP full URL: %s\n", httpRequestLayer->getUrl().c_str());
      }
   }

   for (int i = 0; i < FTP_LOG.size(); i++) {
      if (FTP_LOG[i].first == 1) { // FTP Request
         cout << "Request : " << FTP_LOG[i].second << "\n";
      } else if (FTP_LOG[i].first == 2) { // FTP-DATA (server -> client)
         cout << "FTP-DATA [server -> client] : (" << FTP_LOG[i].second << ")\n";
      } else if (FTP_LOG[i].first == 3) { // FTP-DATA (client -> server)
         cout << "FTP-DATA [client -> server] : (" << FTP_LOG[i].second << ")\n";
      } else {
         cout << "Response : " << FTP_LOG[i].first << " " << FTP_LOG[i].second << '\n';
      }
   }

   /*
   while (!FTP_QUEUE.empty()) {
      cout << FTP_QUEUE.front().first << " " << FTP_QUEUE.front().second << "\n";
      FTP_QUEUE.pop();
   }
   */

  //JSON 쓰기
   ofstream outFile("ftp_log.json", ios::out);
   outFile << root;

   reader->close();

};