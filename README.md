# Prerequisites
   - A free account on Elbrys SDN Developer Lab 
       - Go to http://sdn-developer.elbrys.com and sign-up (or logon with your github account)
       - Follow the [Quickstart](https://github.com/Elbrys/SDN-Developer-Lab/wiki)
   - An OpenFlow switch connected to it (virtual (Mininet) switch will work)
       - Follow the [Quickstart](https://github.com/Elbrys/SDN-Developer-Lab/wiki)

# Sample Applications for OpenNAC API
Sample Applications that work with Elbrys SDN Developer Lab and the OpenNAC API.  See http://dev.elbrys.com   For RESTCONF API sample apps go to [Wiki](https://github.com/Elbrys/SDN-Developer-Lab/wiki).

* app1 -- This is an extremely simple application to demonstrate basics.  It uses default policy to show how traffic may be unblocked for endpoints.
* app2 -- This application demonstrates a subscription using a synchronous application flow.  It listens on a subscription outputing what it receives.  If it receives an 'unmanaged endpoint' event then it will demonstrate setting a policy for that endpoint that allows it to become unblocked.
* app3 -- This application demonstrates a subscription  using an asynchronous application flow (multithreaded).  It provides a menu-driven interface that allows you to see current unmanaged endpoints, set policy on those endpoints, forget endpoints (return them to unmanaged) and reset the application (resetting all openflow flows).
* app4 -- This application is the same as app3, but allows you to define new policies via a configuration file and then set those via the application.
