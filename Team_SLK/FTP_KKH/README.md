# 2020_BoB_NetworkMajor_서예진, 이수진, 김경환 (9-2조)

<h2> WBS </h2>
<div>
  <img width = "1000" src = "https://user-images.githubusercontent.com/58834907/90305123-109aeb80-defa-11ea-961a-6907a66d9c48.jpg">
  </div>

<h2> Terminal Command </h2>
<div>
<img width = "800" src = "https://user-images.githubusercontent.com/58834907/90235811-dd564f00-de5c-11ea-91c0-e82e561f28d8.PNG" >
</div>

<h2> Identical Part of Each Packet </h2>
Packet Sturcture : Ethernet - IP - TCP - HTTP/SMTP/FTP...etc <br>
<br>
Each Layer's info : Layer Type, Total Data, Layer Data, Layer Payload <br>
<br>
&nbsp;&nbsp;&nbsp;Ethernet - Src Mac Address, Dst Mac Address <br>
&nbsp;&nbsp;&nbsp;IP - Src IP Address, Dst IP Address, IP ID <br>
&nbsp;&nbsp;&nbsp;TCP - Src Port, Window size, TCP flags, TCP Sequence Num, TCP Ack Num <br>

<h2> Case 1 : HTTP Pcap File Open </h2>
HTTP packet's info : method, URI, host, user-agent, cookie, URL <br>

<div>
<img width = "800" src = "https://user-images.githubusercontent.com/58834907/90235398-31acff00-de5c-11ea-93a6-a52a39f44906.png">
</div>

<h2> Case 2 : SMTP Pcap File Open </h2>
SMTP packet's info : Response <br>

<div>
<img width = "800" src = "https://user-images.githubusercontent.com/58834907/90235489-5903cc00-de5c-11ea-8e6a-282481152f0f.png">
</div>

<h2> Case 3 : FTP Pcap File Open </h2>
FTP packet's info : Response, Response Code, Response Arg <br>

<div>
<img width = "800" src = "https://user-images.githubusercontent.com/58834907/90235481-56a17200-de5c-11ea-9f41-e4b25f448401.png">
</div>
