# Prerequisites
   - A free account on Elbrys ODL-S 
       - Go to http://sdn-developer.elbrys.com and follow the instructions there
   - An OpenFlow switch connected to it (virtual (Mininet) switch will work)
       - Go to https://github.com/Elbrys/ODL-S/wiki/Connect-Network-Device and follow the instructions there

# ODL-S-Sample-Apps
Sample Applications that work with Elbrys OpenDaylight as a service (ODL-S).  See http://dev.elbrys.com

* app1 -- This is an extremely simple application to demonstrate basics of ODL-S.  It uses default policy to show how traffic may be unblocked for endpoints.
* app2 -- This application demonstrates a subscription to ODL-S using a synchronous application flow.  It listens on a subscription outputing what it receives.  If it receives an 'unmanaged endpoint' event then it will demonstrate setting a policy for that endpoint that allows it to become unblocked.
* app3 -- This application demonstrates a subscription to ODL-S using an asynchronous application flow (multithreaded).  It provides a menu-driven interface that allows you to see current unmanaged endpoints, set policy on those endpoints, forget endpoints (return them to unmanaged) and reset the application (resetting all openflow flows).
