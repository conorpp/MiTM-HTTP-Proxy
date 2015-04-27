MiTM-HTTP-Proxy
===============

A simple, low level http/https proxy server with MiTM pranking features.  

This project consists of two parts

### HTTP Proxy Server
  
    This will proxy all HTTP 1.1 transactions.  
    It will make text substitutions in web pages to demonstrate a MiTM attack.  
    It uses OpenSSL to forge SSL certificates and proxy HTTPS in clear text.  
    This will cause blatant warnings on modern browsers.
    
### ARP Spoofing Process
  
    This targets another machine on the local area network and ARP poisons them.  
    This is to get the target machine to send all packets to the attacker, 
    thinking that the attacker is the router.  
    The attacker will then forward all packets between the router and the target machine.  
    This is unique in this project in that it will pass the packets through the 
    HTTP Proxy server as well to do the MiTM attack demonstration.
