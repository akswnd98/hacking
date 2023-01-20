import socket
import struct


sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
host = socket.gethostbyname(socket.gethostname())
sock.bind((host, 0))
sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

while True:
  data, info = sock.recvfrom(15000)
  ip_header = data[: 20]
  ip_header = struct.unpack('>BBHHBBBBH8B', ip_header)
  ip_src = str(ip_header[9]) + "." + str(ip_header[10]) + "." + str(ip_header[11]) + "." + str(ip_header[12])
  ip_dst = str(ip_header[13]) + "." + str(ip_header[14]) + "." + str(ip_header[15]) + "." + str(ip_header[16])
  ip_v = ip_header[0] >> 4
  ip_header_len = (ip_header[0] - (ip_v << 4)) * 4

  print('ip_src: {}'.format(ip_src))
  print('ip_dst: {}'.format(ip_dst))
  
  if ip_header[7] == 6:
    tcp_header = data[ip_header_len: ip_header_len + 20]
    tcp_header = struct.unpack('>HHIIBBHHH', tcp_header)
    tcp_header_len = (tcp_header[4] >> 4) * 4
    port_src = tcp_header[0]
    port_dst = tcp_header[1]
    print('port_src: {}'.format(port_src))
    print('port_dst: {}'.format(port_dst))
  
  print()
