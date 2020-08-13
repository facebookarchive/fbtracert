# fbtracert

> pronounced: ef-BEE-tracerTEE

## Installing

Requires golang >= 1.5.1:

```bash
go get -d github.com/facebook/fbtracert
go install github.com/facebook/fbtracert
```

```bash
$GOPATH/bin/fbtracert --help
```

## Full documentation

### Fault isolation in ECMP networks via multi-port traceroute

This tool attempts to identify the network component that drops packets by employing the traceroute logic
that explores multiple parallel paths. The following describes the main goroutines and their logic.

### Sender

We start this goroutine for every TTL that we expect on path to the destination. We start with some max TTL
value, and then stop all senders that have TTL above the distance to the target. For every TTL, the sender
loops over a range of source ports, and emits a TCP SYN packet towards the destination with the set target port.
The Sender also emits "Probe" objects on a special channel so that the analysis part may know what packets 
have been injected in the network (srcPort and TTL).

Notice how encode the sending time-stamp and the ttl in the ISN of the TCP SYN packet. This allows for measuring
the probe RTT, and recovering the TTL of the response. Just like regular traceroute, we expect the network to return
us either ICMP Unreachable message (TTL exceeded) or TCP RST message (when we hit the ultimate hop).

The Sender thread stops once it completes the requested number of iterations over the source port range.

### ICMP Receiver

We run only one ICMP receiver goroutine: it is responsible for receiving the ICMP Unreachable messages and recovering
the original probe information from them. We only use the first 8 bytes of the TCP packet embedded into ICMP Unreachable
message, though in IPv6 case we could have more. This is sufficient anyways to recover the TTL and the timestamp of the
original probe.

Upon reception of an ICMP message, we build IcmpResponse struct and forward it to the input work queue of the Resolver
goroutine ensemble. This is needed to resolve the IP address of the node that sent us the response into its DNS name.

### TCP Receiver

Similar to IcmpReceiver in logic, but this goroutine intercepts TCP RST/ACK packets sent by the ultimate destinations of
our probes. These responses are processed and have TTL extracted, and then forwarded to the Resolver thread. We can
work both with close ports (RST expect) and open ports (ACK expected). Be careful and make sure there are no open
connections from your machine to the target on the port you are probing - this may confuse the hell out of TcpReceiver.

### Resolver

This goroutine listens to the incoming Icmp/Tcp Response messages and resolves the names embedded into the Icmp responses.
We start lots of those so we can handle concurrent name resolution. The resolver is effectively a transformation function
on the stream of messages.

### Main goroutine

This one is responsible for starting all other goroutines, and then assembling their output. It is also responsible for
terminating the unnecessary Senders. This is done by seeing what TTL hops actually return TCP RST messages; once we receive
TCP RST for TTL x, we can safely stop all senders for TTL > x

The main loop expects to receive all "Probes" from the channels fed by the Sender goroutines. The Sender will close its
output channels once its done sending. This serves as an indicator that all sending has completed. After that, we 
wait a few more seconds all tell the TcpReceiver and IcmpReceiver to stop by closing their "signal" channel. 

After that, we process all data that the Receivers have fed to the main thread. We need to find the source ports
whose paths show consistent packet loss after a given hop N. We then output these paths as the "suspects" along with the
counts of sent/received packets per hop.

## License
fbtracert is BSD licensed, as found in the [LICENSE](./LICENSE) file.
