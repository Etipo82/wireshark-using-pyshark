import pyshark
from datetime import datetime, timedelta
import time
import os
import subprocess
import webbrowser

def menu():
  my_filter = input('\nFilter pcap file?\n\n'
                    'TYPE 1: Yes\n'
                    'Type 2: No\n'
                    'TYPE 3: QUIT\n\n'
                    '>>> ')
  if my_filter == "1":
        show_pcap_filter()
  elif my_filter == "2":
        show_pcap()
  elif my_filter == "3":
        quit()
  else:
    print("Not a valid choice, try again: ")


def print_info_layer(packet):
  try:
    ip_src = packet.ip.src
  except AttributeError:
    ip_src = 'N/A'
  try:
    ip_dest = packet.ip.dst
  except AttributeError:
    ip_dest = 'N/A'
  try:
    imsi = packet.gsm_map.e212_imsi
  except AttributeError:
    imsi = 'N/A'
  try:
    mnc = packet.gsm_map.e212_mnc
  except AttributeError:
    mnc = 'N/A'
  try:
    mcc = packet.gsm_map.e212_mcc
  except AttributeError:
    mcc = 'N/A'
  try:
    otid = packet.tcap.otid
  except AttributeError:
    otid = 'N/A'
  try:
    tid = packet.tcap.tid
  except AttributeError:
    tid = 'N/A'
  try:
    calling = packet.sccp.calling_digits
  except AttributeError:
    calling = 'N/A'
  try:
    called = packet.sccp.called_digits
  except AttributeError:
    called = 'N/A'
  print("\n\n[src IP:] "+ip_src+
        "\t[dst IP:] "+ip_dest+
        "\t[IMSI:] "+imsi+
        "\t[MNC]: "+mnc+
        "\t[MCC]: "+mcc+
        "\t[otid]: "+otid+
        "\t[tid]: "+tid+
        "\t[Calling MDN]: "+calling+
        "\t[Called MDN]: "+called)



def show_pcap_filter():
  set_my_filter=input('\n\nSet your filter: ')
  cap = pyshark.FileCapture(my_file, display_filter=set_my_filter)
  for pkt in cap:
    cap.apply_on_packets(print_info_layer)
    break


def show_pcap():
  cap = pyshark.FileCapture(my_file)
  for pkt in cap:
    cap.apply_on_packets(print_info_layer)
    break


if __name__ == '__main__':
    while True:
      my_file = input('\nEnter file (<file_name>.pcap): ')
      menu()



