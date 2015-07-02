# ODL-S-Sample-Apps
Sample Applications that work with Elbrys OpenDaylight as a service (ODL-S).

* app1 -- This is an extremely simple application to demonstrate basics of ODL-S.  It uses default policy to show how traffic may be unblocked for endpoints.
* app2 -- This application demonstrates a subscription to ODL-S.  It listens on a subscription outputing what it receives.  If it receives an 'unmanaged endpoint' event then it will demonstrate setting a policy for that endpoint that allows it to become unblocked.
