Nifi RouteIP Processor

Description

Many flow files we deal with contain IP addresses in its contents or in their attributes.
For example, flowfiles from ListenTCP or ListerUDP processor contain attributes named "tcp.sender" or "udp.sender".

Under some circumstances, we need to route these flowfiles by extracted ip addresses against a subnet or a list of subnets in cidr notations.
Since an IP address matching a cidr is not easy to be implemented through regex or nifi expression language, it is nice to have a custom processor 
to do that.

RouteIP processor supports two ways to extract ip addresses:
1. nifi expression language.
For example, for flowfiles from ListenTcp, source ip can be extracted as ${tcp.sender}

2. regex
For example, in flowfile each line has format:
srcip=xx.xx.xx.xx message = 
We can use a regex to extract the ip address.

RouteIP processor compares these extracted ip to a comma seperated cidr list configured as a property of the processor, 
and route the flowfiles to matched or unmatched relationship.

For regex, it compares each line of flowfiles to see if it is matched, then route the line to matched.
For example, you have following flowfile

srcip:10.2.0.13
srcip:10.2.1.123

and you have regex "souce ip:(.*)", as well as cidr list "10.2.0.0/24", 
then the first line will be routed to matched relationship while the second line to unmatched.

Build

Checkout the project, go to the directory YUSHUN, run:
$ mvn install

Deployment
$ cd nifi-cidr-nar/target
$ cp nifi-cidr-nar-1.0.nar your-nifi-home/lib
then restart your nifi, you can use RouteIP processor in your nifi UI.

Acknowledgement
It is inspired by RouteText processor.
Currently it only suports IP v4.



