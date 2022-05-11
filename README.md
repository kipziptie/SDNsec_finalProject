# Introduction
The scope of this document is to present our proposal regarding the final assignment of “Network Security based on SDN/NFV technologies” course. Specifically, we will specify the technology stack that we shall use, the scenario of our project as well as a detailed explanation of the components that we shall use in order to implement this project.
# Technology Stack
Grafana.
SNORT IDS.
Mininet.
Ryu manager.
Python.
# Scenario
There exists a server hosting a simple web service. Snort interfaces with the firewall to label traffic as attack traffic or normal traffic. Attack traffic is reported to the application via Grafana. The application can apply countermeasures such as a moving target defense (move the server) or a traffic redirection to the honeypot (in case intelligence gathering is desired to better understand the adversary). There will be attackers and legitimate users making server requests. The objective is to construct a network which can defend against attacks while not impacting service to the legitimate users. 

# Demo

First, to launch the mininet topology perform the following command in the scripts directory:

```
sudo bash start_manager.sh
```
