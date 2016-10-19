/**
 * Copyright (c) 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/golang/glog"
	"github.com/olekukonko/tablewriter"
)

const (
	icmpHdrSize      int = 8
	minTCPHdrSize    int = 20
	maxTCPHdrSize    int = 60
	minIP4HeaderSize int = 20
	maxIP4HeaderSize int = 60
	ip6HeaderSize    int = 40
)

func main() {
	var (
		maxTTL       = flag.Int("maxTTL", 30, "The maximum ttl to use")
		minTTL       = flag.Int("minTTL", 1, "The ttl to start at")
		maxSrcPorts  = flag.Int("maxSrcPorts", 256, "The maximum number of source ports to use")
		maxTime      = flag.Int("maxTime", 60, "The time to run the process for")
		targetPort   = flag.Int("targetPort", 22, "The target port to trace to")
		probeRate    = flag.Int("probeRate", 96, "The probe rate per ttl layer")
		tosValue     = flag.Int("tosValue", 140, "The TOS/TC to use in probes")
		numResolvers = flag.Int("numResolvers", 32, "The number of DNS resolver goroutines")
		addrFamily   = flag.String("addrFamily", "ip4", "The address family (ip4/ip6) to use for testing")
		maxColumns   = flag.Int("maxColumns", 4, "Maximum number of columns in report tables")
		showAll      = flag.Bool("showAll", false, "Show all paths, regardless of loss detection")
		srcAddr      = flag.String("srcAddr", "", "The source address for pings, default to auto-discover")
		jsonOutput   = flag.Bool("jsonOutput", false, "Output raw JSON data")
		baseSrcPort  = flag.Int("baseSrcPort", 32768, "The base source port to start probing from")
	)
	flag.Parse()
	if flag.Arg(0) == "" {
		fmt.Fprintf(os.Stderr, "Must specify a target\n")
		return
	}

	numIters := int(*maxTime * *probeRate / *maxSrcPorts)
	if numIters <= 1 {
		fmt.Fprintf(os.Stderr, "Number of iterations too low, increase probe rate / run time or decrease src port range...\n")
		return
	}

	source, err := getSourceAddr(*addrFamily, *srcAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not identify a source address to trace from\n")
		return
	}

	fmt.Fprintf(os.Stderr, "Starting fbtracert with %d probes per second/ttl, base src port %d and with the port span of %d\n", *probeRate, *baseSrcPort, *maxSrcPorts)
	if flag.Lookup("logtostderr").Value.String() == "false" {
		fmt.Fprintf(os.Stderr, "Use '-logtostderr=true' cmd line option to see GLOG output\n")
	}

	// Start Senders
	target := flag.Arg(0)
	var senderWG sync.WaitGroup
	senderWG.Add(*maxTTL)
	probes := make(chan Probe)
	ctx := context.Background()
	senderCancels := make(map[int]context.CancelFunc)
	for ttl := *minTTL; ttl <= *maxTTL; ttl++ {
		ctx, senderCancels[ttl] = context.WithCancel(ctx)
		err := Sender(ctx, &senderWG, source, *addrFamily, target, *targetPort, *baseSrcPort, *maxSrcPorts, numIters, ttl, *probeRate, *tosValue, probes)
		if err != nil {
			glog.Errorf("Failed to start sender for ttl %d, %s", ttl, err)
			if err.Error() == "operation not permitted" {
				glog.Error(" -- are you running with the correct privileges?")
			}
			return
		}
	}
	go func() {
		senderWG.Wait()
		close(probes)
	}()

	// collect ICMP unreachable messages for our probes
	recvDone := make(chan struct{}) // channel to tell receivers to stop
	icmpResp, err := ICMPReceiver(recvDone, source, *addrFamily)
	if err != nil {
		glog.Errorf("Failed to start ICMP receiver, %s", err)
		return
	}

	var resolveWG sync.WaitGroup
	resolveWG.Add(*numResolvers)
	resolvedICMP := make(chan ICMPResponse)
	for i := 0; i < *numResolvers; i++ {
		go Resolver(&resolveWG, icmpResp, resolvedICMP)
	}
	go func() {
		resolveWG.Wait()
		close(resolvedICMP)
	}()

	// collect TCP RST's from the target
	targetAddr, err := resolveName(target, *addrFamily)
	tcpResp, err := TCPReceiver(recvDone, source, *addrFamily, targetAddr.String(), *baseSrcPort, *baseSrcPort+*maxSrcPorts, *targetPort, *maxTTL)
	if err != nil {
		glog.Errorf("Failed to start TCP receiver, %s", err)
		return
	}

	// maps that store various counters per source port/ttl
	// e..g sent, for every soruce port, contains vector
	// of sent packets for each TTL
	sent := make(map[int] /*src Port */ []int /* pkts sent */)
	rcvd := make(map[int] /*src Port */ []int /* pkts rcvd */)
	hops := make(map[int] /*src Port */ []string /* hop name */)

	for srcPort := *baseSrcPort; srcPort < *baseSrcPort+*maxSrcPorts; srcPort++ {
		sent[srcPort] = make([]int, *maxTTL)
		rcvd[srcPort] = make([]int, *maxTTL)
		hops[srcPort] = make([]string, *maxTTL)
		//hops[srcPort][*maxTTL-1] = target

		for i := 0; i < *maxTTL; i++ {
			hops[srcPort][i] = "?"
		}
	}

	var names []string                 // this store DNS names of all nodes that ever replied to us
	flappedPorts := make(map[int]bool) // src ports that changed their paths in process of tracing
	lastClosed := *maxTTL

receiveLoop:
	for {
		select {
		case probe, ok := <-probes:
			if !ok {
				// collect all probe specs emitted by senders
				// once all senders terminate, tell receivers to quit too
				probes = nil
				glog.V(2).Infoln("All senders finished!")
				// tell receivers to stop receiving
				close(recvDone)
				continue
			}
			sent[probe.srcPort][probe.ttl-1]++
		case resp, ok := <-resolvedICMP:
			if !ok {
				resolvedICMP = nil
				continue
			}
			rcvd[resp.srcPort][resp.ttl-1]++
			currName := hops[resp.srcPort][resp.ttl-1]
			if currName != "?" && currName != resp.fromName {
				glog.V(2).Infof("%d: Source port %d flapped at ttl %d from: %s to %s\n", time.Now().UnixNano()/(1000*1000), resp.srcPort, resp.ttl, currName, resp.fromName)
				flappedPorts[resp.srcPort] = true
			}
			hops[resp.srcPort][resp.ttl-1] = resp.fromName
			// accumulate all names for processing later
			// XXX: we may have duplicates, which is OK,
			// but not very efficient
			names = append(names, resp.fromName)
		case resp, ok := <-tcpResp:
			if !ok {
				tcpResp = nil
				continue
			}
			// stop all senders sending above this ttl, since they are not needed
			// XXX: this is not always optimal, i.e. we may receive TCP RST for
			// a port mapped to a short WAN path, and it would tell us to terminate
			// probing at higher TTL, thus cutting visibility on "long" paths
			// however, this mostly concerned that last few hops...
			senderCancels[resp.ttl]()
			// update the last closed ttl, so we don't double-close the channels
			if resp.ttl < lastClosed {
				lastClosed = resp.ttl
			}
			rcvd[resp.srcPort][resp.ttl-1]++
			hops[resp.srcPort][resp.ttl-1] = target
		default:
			if resolvedICMP == nil && tcpResp == nil && probes == nil {
				break receiveLoop
			}
		}
	}

	for srcPort, hopVector := range hops {
		for i := range hopVector {
			// truncate lists once we hit the target name
			if hopVector[i] == target && i < *maxTTL-1 {
				sent[srcPort] = sent[srcPort][:i+1]
				rcvd[srcPort] = rcvd[srcPort][:i+1]
				hopVector = hopVector[:i+1]
				break
			}
		}
	}

	if len(flappedPorts) > 0 {
		glog.Infof("A total of %d ports out of %d changed their paths while tracing\n", len(flappedPorts), *maxSrcPorts)
	}

	lossyPathSent := make(map[int] /*src port */ []int)
	lossyPathRcvd := make(map[int] /* src port */ []int)
	lossyPathHops := make(map[int] /*src port*/ []string)

	// process the accumulated data, find and output lossy paths
	for port, sentVector := range sent {
		if flappedPorts[port] {
			continue
		}
		if rcvdVector, ok := rcvd[port]; ok {
			norm, err := normalizeRcvd(sentVector, rcvdVector)

			if err != nil {
				glog.Errorf("Could not normalize %v / %v", rcvdVector, sentVector)
				continue
			}

			if isLossy(norm) || *showAll {
				hosts := make([]string, len(norm))
				for i := range norm {
					hosts[i] = hops[port][i]
				}
				lossyPathSent[port] = sentVector
				lossyPathRcvd[port] = rcvdVector
				lossyPathHops[port] = hosts
			}
		} else {
			glog.Errorf("No responses received for port %d", port)
		}
	}

	if len(lossyPathHops) > 0 {
		if *jsonOutput {
			printLossyPathsJSON(lossyPathSent, lossyPathRcvd, lossyPathHops, lastClosed+1)
		} else {
			printLossyPaths(lossyPathSent, lossyPathRcvd, lossyPathHops, *maxColumns, lastClosed+1)
		}
		return
	}
	glog.Infof("Did not find any faulty paths\n")
}

//
// Discover the source address for pinging
//
func getSourceAddr(af string, srcAddr string) (*net.IP, error) {

	if srcAddr != "" {
		addr, err := net.ResolveIPAddr(af, srcAddr)
		if err != nil {
			return nil, err
		}
		return &addr.IP, nil
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {
			if (ipnet.IP.To4() != nil && af == "ip4") || (ipnet.IP.To4() == nil && af == "ip6") {
				return &ipnet.IP, nil
			}
		}
	}
	return nil, fmt.Errorf("Could not find a source address in af %s", af)
}

// Resolve given hostname/address in the given address family
func resolveName(dest string, af string) (*net.IP, error) {
	addr, err := net.ResolveIPAddr(af, dest)
	if err != nil {
		return nil, err
	}
	return &addr.IP, nil
}

// Probe is emitted by sender
type Probe struct {
	srcPort int
	ttl     int
}

// ICMPResponse is emitted by ICMPReceiver
type ICMPResponse struct {
	Probe
	fromAddr net.IP
	fromName string
	rtt      uint32
}

// TCPResponse is emitted by TCPReceiver
type TCPResponse struct {
	Probe
	rtt uint32
}

// TCPReceiver Feeds on TCP RST messages we receive from the end host; we use lots of parameters to check if the incoming packet
// is actually a response to our probe. We create TCPResponse structs and emit them on the output channel
func TCPReceiver(done <-chan struct{}, srcAddr *net.IP, af string, targetAddr string, probePortStart, probePortEnd, targetPort, maxTTL int) (chan TCPResponse, error) {

	glog.V(2).Infoln("TCPReceiver starting...")

	conn, err := net.ListenPacket(af+":tcp", srcAddr.String())
	if err != nil {
		return nil, err
	}

	// we'll be writing the TCPResponse structs to this channel
	out := make(chan TCPResponse)

	go func() {
		defer conn.Close()
		defer close(out)
		ipHdrSize := 0
		if af == "ip4" {
			ipHdrSize = 20
		}
		packet := make([]byte, ipHdrSize+maxTCPHdrSize)

		for {
			select {
			case <-done:
				glog.V(2).Infoln("TCPReceiver terminating...")
				return
			default:
				conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				n, from, err := conn.ReadFrom(packet)
				if err != nil {
					if !strings.Contains(err.Error(), "i/o timeout") {
						glog.V(2).Infoln("tcpreceiver: error reading from network:", err)
					}
					continue
				}

				// IP + TCP header size
				if n < ipHdrSize+minTCPHdrSize {
					continue
				}

				// is that from the target port we expect?
				tcpHdr := parseTCPHeader(packet[ipHdrSize:n])
				if int(tcpHdr.Source) != targetPort {
					continue
				}

				// is that TCP RST TCP ACK?
				if tcpHdr.Flags&RST != RST && tcpHdr.Flags&ACK != ACK {
					continue
				}

				// is that from our target?
				if from.String() != targetAddr {
					continue
				}

				glog.V(4).Infof("Received TCP response message %d: %x\n", len(packet), packet)

				// we extract the original TTL and timestamp from the ack number
				ackNum := tcpHdr.AckNum - 1
				ttl := int(ackNum >> 24)

				if ttl > maxTTL || ttl < 1 {
					continue
				}

				// recover the time-stamp from the ack #
				ts := ackNum & 0x00ffffff
				now := uint32(time.Now().UnixNano()/(1000*1000)) & 0x00ffffff

				// received timestamp is higher than local time; it is possible
				// that ts == now, since our clock resolution is coarse
				if ts > now {
					continue
				}

				out <- TCPResponse{Probe: Probe{srcPort: int(tcpHdr.Destination), ttl: ttl}, rtt: now - ts}
			}
		}
	}()

	return out, nil
}

// ICMPReceiver runs on its own collecting ICMP responses until its explicitly told to stop
func ICMPReceiver(done <-chan struct{}, srcAddr *net.IP, af string) (chan ICMPResponse, error) {
	var minInnerIPHdrSize int
	var icmpMsgType byte
	var listenNet string
	switch af {
	case "ip4":
		minInnerIPHdrSize = minIP4HeaderSize // the size of the original IPv4 header that was on the TCP packet sent out
		icmpMsgType = 11                     // time to live exceeded
		listenNet = "ip4:1"                  // IPv4 ICMP proto number
	case "ip6":
		minInnerIPHdrSize = ip6HeaderSize // this is the size of IPv6 header of the original TCP packet we used in the probes
		icmpMsgType = 3                   // time to live exceeded
		listenNet = "ip6:58"              // IPv6 ICMP proto number
	default:
		return nil, fmt.Errorf("sender: unsupported network %q", af)
	}

	conn, err := icmp.ListenPacket(listenNet, srcAddr.String())
	if err != nil {
		return nil, err
	}

	glog.V(2).Infoln("ICMPReceiver is starting...")

	out := make(chan ICMPResponse)

	go func() {
		defer conn.Close()
		defer close(out)
		packet := make([]byte, icmpHdrSize+maxIP4HeaderSize+maxTCPHdrSize)
		for {
			select {
			case <-done:
				glog.V(2).Infoln("ICMPReceiver terminating...")
				return
			default:
				conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				n, from, err := conn.ReadFrom(packet)
				if err != nil {
					if !strings.Contains(err.Error(), "i/o timeout") {
						glog.V(2).Infoln("icmpreceiver: error reading from network:", err)
					}
					continue
				}

				if n < icmpHdrSize+minInnerIPHdrSize+minTCPHdrSize {
					continue
				}

				// not ttl exceeded
				if packet[0] != icmpMsgType || packet[1] != 0 {
					continue
				}

				glog.V(4).Infof("Received ICMP response message %d: %x\n", n, packet[:n])

				tcpHdr := parseTCPHeader(packet[icmpHdrSize+minInnerIPHdrSize : n])

				ttl := int(tcpHdr.SeqNum) >> 24                               // extract ttl bits from the ISN
				ts := tcpHdr.SeqNum & 0x00ffffff                              // extract the timestamp from the ISN
				now := uint32(time.Now().UnixNano()/(1000*1000)) & 0x00ffffff // scale the current time
				out <- ICMPResponse{Probe: Probe{srcPort: int(tcpHdr.Source), ttl: ttl}, fromAddr: net.ParseIP(from.String()), rtt: now - ts}
			}
		}
	}()

	return out, nil
}

// Resolver resolves names in incoming ICMPResponse messages
// Everything else is passed through as is
func Resolver(wg *sync.WaitGroup, input <-chan ICMPResponse, out chan<- ICMPResponse) {
	defer wg.Done()
	for val := range input {
		val.fromName = val.fromAddr.String()
		names, err := net.LookupAddr(val.fromAddr.String())
		if err == nil {
			val.fromName = names[0]
		}
		out <- val
	}
}

// Sender generates TCP SYN packet probes with given TTL at given packet per second rate
// The packet descriptions are published to the output channel as Probe messages
// As a side effect, the packets are injected into raw socket
func Sender(ctx context.Context, wg *sync.WaitGroup, srcAddr *net.IP, af, dest string, dstPort, baseSrcPort, maxSrcPorts, maxIters, ttl, pps, tos int, out chan<- Probe) error {
	glog.V(2).Infof("Sender for ttl %d starting\n", ttl)

	dstAddr, err := resolveName(dest, af)
	if err != nil {
		return err
	}

	conn, err := net.ListenPacket(af+":tcp", srcAddr.String())
	if err != nil {
		return err
	}

	switch af {
	case "ip4":
		conn := ipv4.NewPacketConn(conn)
		if err != nil {
			return err
		}
		if err := conn.SetTTL(ttl); err != nil {
			return err
		}
		if err := conn.SetTOS(tos); err != nil {
			return err
		}
	case "ip6":
		conn := ipv6.NewPacketConn(conn)
		if err := conn.SetHopLimit(ttl); err != nil {
			return err
		}
		if err := conn.SetTrafficClass(tos); err != nil {
			return err
		}
	default:
		return fmt.Errorf("sender: unsupported network %q", af)
	}

	// spawn a new goroutine and return the channel to be used for reading
	go func() {
		defer conn.Close()
		defer wg.Done()

		delay := time.Duration(1000/pps) * time.Millisecond

		for i := 0; i < maxSrcPorts*maxIters; i++ {
			srcPort := baseSrcPort + i%maxSrcPorts
			now := uint32(time.Now().UnixNano()/(1000*1000)) & 0x00ffffff
			seqNum := ((uint32(ttl) & 0xff) << 24) | (now & 0x00ffffff)
			packet := makeTCPHeader(af, srcAddr, dstAddr, srcPort, dstPort, seqNum)

			if _, err := conn.WriteTo(packet, &net.IPAddr{IP: *dstAddr}); err != nil {
				glog.Errorf("Error sending packet %s\n", err)
				break
			}

			probe := Probe{srcPort: srcPort, ttl: ttl}
			start := time.Now() // grab time before blocking on send channel
			select {
			case out <- probe:
				end := time.Now()
				jitter := time.Duration(((rand.Float64()-0.5)/20)*1000/float64(pps)) * time.Millisecond
				if end.Sub(start) < delay+jitter {
					time.Sleep(delay + jitter - (end.Sub(start)))
				}
			case <-ctx.Done():
				glog.V(2).Infof("Sender for ttl %d exiting prematurely\n", ttl)
				return
			}
		}
		glog.V(2).Infoln("Sender done")
	}()

	return nil
}

//
// Normalize rcvd by send count to get the hit rate
//
func normalizeRcvd(sent, rcvd []int) ([]float64, error) {
	if len(rcvd) != len(sent) {
		return nil, fmt.Errorf("Length mismatch for sent/rcvd")
	}

	result := make([]float64, len(rcvd))
	for i := range sent {
		result[i] = float64(rcvd[i]) / float64(sent[i])
	}

	return result, nil
}

//
// Detect a pattern where all samples after
// a sample [i] have lower hit rate than [i]
// this normally indicates a breaking point after [i]
//
func isLossy(hitRates []float64) bool {
	var found bool
	var segLen int
	for i := 0; i < len(hitRates)-1 && !found; i++ {
		found = true
		segLen = len(hitRates) - i
		for j := i + 1; j < len(hitRates); j++ {
			if hitRates[j] >= hitRates[i] {
				found = false
				break
			}
		}
	}
	// do not alarm on single-hop segment
	if segLen > 2 {
		return found
	}
	return false
}

//
// print the paths reported as having losses
//
func printLossyPaths(sent, rcvd map[int] /* src port */ []int, hops map[int] /* src port */ []string, maxColumns, maxTTL int) {
	var allPorts []int

	for srcPort := range hops {
		allPorts = append(allPorts, srcPort)
	}

	// split in multiple tables to fit the columns on the screen
	for i := 0; i < len(allPorts)/maxColumns; i++ {
		data := make([][]string, maxTTL)
		table := tablewriter.NewWriter(os.Stdout)
		header := []string{"TTL"}

		maxOffset := (i + 1) * maxColumns
		if maxOffset > len(allPorts) {
			maxOffset = len(allPorts)
		}

		for _, srcPort := range allPorts[i*maxColumns : maxOffset] {
			header = append(header, fmt.Sprintf("port: %d", srcPort), fmt.Sprintf("sent/rcvd"))
		}

		table.SetHeader(header)

		for ttl := 0; ttl < maxTTL-1; ttl++ {
			data[ttl] = make([]string, 2*(maxOffset-i*maxColumns)+1)
			data[ttl][0] = fmt.Sprintf("%d", ttl+1)
			for j, srcPort := range allPorts[i*maxColumns : maxOffset] {
				data[ttl][2*j+1] = hops[srcPort][ttl]
				data[ttl][2*j+2] = fmt.Sprintf("%02d/%02d", sent[srcPort][ttl], rcvd[srcPort][ttl])
			}
		}

		for _, v := range data {
			table.Append(v)
		}

		table.Render()
		fmt.Fprintf(os.Stdout, "\n")
	}
}

// Report defines a JSON report from go/fbtracert
type Report struct {
	// The path map
	Paths map[string] /* srcPort */ []string /* path hops */
	// Probe count sent per source port/hop name
	Sent map[string][]int
	// Probe count received per source port/hop name
	Rcvd map[string][]int
}

func newReport() (report Report) {
	report.Paths = make(map[string][]string)
	report.Sent = make(map[string][]int)
	report.Rcvd = make(map[string][]int)

	return report
}

//
// Raw Json output for external program to analyze
//
func printLossyPathsJSON(sent, rcvd map[int] /* src port */ []int, hops map[int] /* src port */ []string, maxTTL int) {
	var report = newReport()

	for srcPort, path := range hops {
		report.Paths[fmt.Sprintf("%d", srcPort)] = path
		report.Sent[fmt.Sprintf("%d", srcPort)] = sent[srcPort]
		report.Rcvd[fmt.Sprintf("%d", srcPort)] = rcvd[srcPort]
	}

	b, err := json.MarshalIndent(report, "", "\t")
	if err != nil {
		glog.Errorf("Could not generate JSON %s", err)
		return
	}
	fmt.Fprintf(os.Stdout, "%s\n", b)
}
