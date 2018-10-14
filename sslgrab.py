#!/usr/bin/python3
import time
import sys
import threading
import logging
from queue import Queue
import netaddr
import ssl
import socket
import os
import json
import M2Crypto
import OpenSSL
import traceback

# List of ports to scan for TLS certificates
ports = [80, 443, 636, 465, 995, 993]
ports = [443]

class getCertificate (threading.Thread):
  def __init__(self, id, hosts):
    logging.debug("Thread-%d: Started" % id)
    threading.Thread.__init__(self)
    self.hosts = hosts
    self.id = id

  def run(self):
    while self.hosts.empty() == False:
      ip = self.hosts.get()
      logging.debug("Thread-%d: Reading from %s" % (self.id, ip))
      get_data(ip, self.id)
      self.hosts.task_done()
    logging.debug("Thread-%d: finished" % self.id)

def get_data(ip, threadId):
    for port in ports:
      d = {"host": ip, "port": port, "certificate": ""}
      try:
        cert = ssl.get_server_certificate((ip, port))
        x509 = M2Crypto.X509.load_cert_string(cert)
        openssl_x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        d['status'] = "success"
        d['certificate'] = ''.join(cert.split("\n")[1:-2])
        d['subject'] = {str(comp[0], 'utf-8'): str(comp[1], 'utf-8') for comp in openssl_x509.get_subject().get_components()}
        d['issuer'] = {str(comp[0], 'utf-8'): str(comp[1], 'utf-8') for comp in openssl_x509.get_issuer().get_components()}
        d['version'] = openssl_x509.get_version()
        d['serialNumber'] = str(openssl_x509.get_serial_number())
        d['notBefore'] = str(openssl_x509.get_notBefore(), 'utf-8')
        d['notAfter'] = str(openssl_x509.get_notAfter(), 'utf-8')
        d['extension'] = {}
        for i in range(0,x509.get_ext_count()):
            extension = x509.get_ext_at(i)
            ext_name = extension.get_name()
            if ext_name != None:
              d['extension'][ext_name] = str(extension.get_value())

      except Exception as e:
          d['status'] = "socket error: {}".format(e)
          #traceback.print_exc()
      try:
          print(json.dumps(d), flush=True)
      except TypeError as e:
          print("TypeError: {}".format(d), file=sys.stderr)
          pass

if __name__ == '__main__':
  logger = logging.getLogger()
  logger.setLevel(logging.INFO)
  hosts = Queue()

  # Load list of hosts from file
  filename = sys.argv[1]
  with open(filename) as f:
    for network in f:
        for addr in netaddr.IPNetwork(network):
          hosts.put(str(addr))

  t = []
  numThreads = 1000
  socket.setdefaulttimeout(2)
  for i in range(numThreads):
    thread1 = getCertificate(i, hosts)
    thread1.start()
    t.append(thread1)
