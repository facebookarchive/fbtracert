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
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/golang/glog"
	"github.com/olekukonko/tablewriter"
)

//
// Command line flags
//

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
	senderDone := make([]chan struct{}, *maxTTL) // this will catch senders quitting - we have one sender per ttl
	var probes []chan interface{}
	for ttl := *minTTL; ttl <= *maxTTL; ttl++ {
		senderDone[ttl-1] = make(chan struct{})
		c, err := Sender(senderDone[ttl-1], source, *addrFamily, target, *targetPort, *baseSrcPort, *maxSrcPorts, numIters, ttl, *probeRate, *tosValue)
		if err != nil {
			glog.Errorf("Failed to start sender for ttl %d, %s", ttl, err)
			if err.Error() == "operation not permitted" {
				glog.Error(" -- are you running with the correct privileges?")
			}
			return
		}
		probes = append(probes, c)
	}

	// collect ICMP unreachable messages for our probes
	recvDone := make(chan struct{}) // channel to tell receivers to stop
	icmpResp, err := ICMPReceiver(recvDone, *addrFamily)
	if err != nil {
		return
	}

	// collect TCP RST's from the target
	targetAddr, err := resolveName(target, *addrFamily)
	tcpResp, err := TCPReceiver(recvDone, source, *addrFamily, targetAddr.String(), *baseSrcPort, *baseSrcPort+*maxSrcPorts, *targetPort, *maxTTL)
	if err != nil {
		return
	}

	// add DNS name resolvers to the mix
	var resolved []chan interface{}
	unresolved := merge(tcpResp, icmpResp)

	for i := 0; i < *numResolvers; i++ {
		c, err := Resolver(unresolved)
		if err != nil {
			return
		}
		resolved = append(resolved, c)
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

	// collect all probe specs emitted by senders
	// once all senders terminate, tell receivers to quit too
	go func() {
		for val := range merge(probes...) {
			probe := val.(Probe)
			sent[probe.srcPort][probe.ttl-1]++
		}
		glog.V(2).Infoln("All senders finished!")
		// give receivers time to catch up on in-flight data
		time.Sleep(2 * time.Second)
		// tell receivers to stop receiving
		close(recvDone)
	}()

	// this store DNS names of all nodes that ever replied to us
	var names []string

	// src ports that changed their paths in process of tracing
	var flappedPorts = make(map[int]bool)

	lastClosed := *maxTTL
	for val := range merge(resolved...) {
		switch val.(type) {
		case ICMPResponse:
			resp := val.(ICMPResponse)
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
		case TCPResponse:
			resp := val.(TCPResponse)
			// stop all senders sending above this ttl, since they are not needed
			// XXX: this is not always optimal, i.e. we may receive TCP RST for
			// a port mapped to a short WAN path, and it would tell us to terminate
			// probing at higher TTL, thus cutting visibility on "long" paths
			// however, this mostly concerned that last few hops...
			for i := resp.ttl; i < lastClosed; i++ {
				close(senderDone[i])
			}
			// update the last closed ttl, so we don't double-close the channels
			if resp.ttl < lastClosed {
				lastClosed = resp.ttl
			}
			rcvd[resp.srcPort][resp.ttl-1]++
			hops[resp.srcPort][resp.ttl-1] = target
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
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
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
	fromAddr *net.IP
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
func TCPReceiver(done <-chan struct{}, srcAddr *net.IP, af string, targetAddr string, probePortStart, probePortEnd, targetPort, maxTTL int) (chan interface{}, error) {

	glog.V(2).Infoln("TCPReceiver starting...")

	conn, err := net.ListenPacket(af+":6", srcAddr.String())
	if err != nil {
		return nil, err
	}

	ipHdrSize := 0
	if af == "ip4" {
		ipHdrSize = 20
	}

	// we'll be writing the TCPResponse structs to this channel
	out := make(chan interface{})

	// IP + TCP header, this channel is fed from the socket
	recv := make(chan TCPResponse)
	go func() {
		const tcpHdrSize int = 20
		packet := make([]byte, ipHdrSize+tcpHdrSize)

		for {
			n, from, err := conn.ReadFrom(packet)
			// parent has closed the socket likely
			if err != nil {
				break
			}

			// IP + TCP header size
			if n < ipHdrSize+tcpHdrSize {
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

			recv <- TCPResponse{Probe: Probe{srcPort: int(tcpHdr.Destination), ttl: ttl}, rtt: now - ts}
		}
	}()

	go func() {
		defer conn.Close()
		defer close(out)
		for {
			select {
			case response := <-recv:
				out <- response
			case <-done:
				glog.V(2).Infoln("TCPReceiver terminating...")
				return
			}
		}
	}()

	return out, nil
}

// ICMPReceiver runs on its own collecting ICMP responses until its explicitly told to stop
func ICMPReceiver(done <-chan struct{}, af string) (chan interface{}, error) {
	var recvSocket int
	var err error
	var outerIPHdrSize int
	var innerIPHdrSize int
	var icmpMsgType byte

	const (
		icmpHdrSize int = 8
		tcpHdrSize  int = 8
	)

	switch {
	case af == "ip4":
		recvSocket, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
		// IPv4 raw socket always prepend the transport IPv4 header
		outerIPHdrSize = 20
		// the size of the original IPv4 header that was on the TCP packet sent out
		innerIPHdrSize = 20
		// hardcoded: time to live exceeded
		icmpMsgType = 11
	case af == "ip6":
		recvSocket, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
		// IPv6 raw socket does not prepend the original transport IPv6 header
		outerIPHdrSize = 0
		// this is the size of IPv6 header of the original TCP packet we used in the probes
		innerIPHdrSize = 40
		// time to live exceeded
		icmpMsgType = 3
	}

	if err != nil {
		return nil, err
	}

	glog.V(2).Infoln("ICMPReceiver is starting...")

	recv := make(chan interface{})

	go func() {
		// TODO: remove hardcode; 20 bytes for IP header, 8 bytes for ICMP header, 8 bytes for TCP header
		packet := make([]byte, outerIPHdrSize+icmpHdrSize+innerIPHdrSize+tcpHdrSize)
		for {
			n, from, err := syscall.Recvfrom(recvSocket, packet, 0)
			if err != nil {
				break
			}
			// extract the 8 bytes of the original TCP header
			if n < outerIPHdrSize+icmpHdrSize+innerIPHdrSize+tcpHdrSize {
				continue
			}
			// not ttl exceeded
			if packet[outerIPHdrSize] != icmpMsgType || packet[outerIPHdrSize+1] != 0 {
				continue
			}
			glog.V(4).Infof("Received ICMP response message %d: %x\n", len(packet), packet)
			tcpHdr := parseTCPHeader(packet[outerIPHdrSize+icmpHdrSize+innerIPHdrSize : n])

			var fromAddr net.IP

			switch {
			case af == "ip4":
				fromAddr = net.IP(from.(*syscall.SockaddrInet4).Addr[:])
			case af == "ip6":
				fromAddr = net.IP(from.(*syscall.SockaddrInet6).Addr[:])
			}

			// extract ttl bits from the ISN
			ttl := int(tcpHdr.SeqNum) >> 24

			// extract the timestamp from the ISN
			ts := tcpHdr.SeqNum & 0x00ffffff
			// scale the current time
			now := uint32(time.Now().UnixNano()/(1000*1000)) & 0x00ffffff
			recv <- ICMPResponse{Probe: Probe{srcPort: int(tcpHdr.Source), ttl: ttl}, fromAddr: &fromAddr, rtt: now - ts}
		}
	}()

	out := make(chan interface{})
	go func() {
		defer syscall.Close(recvSocket)
		defer close(out)
		for {
			select {
			// read ICMP struct
			case response := <-recv:
				out <- response
			case <-done:
				glog.V(2).Infoln("ICMPReceiver done")
				return
			}
		}
	}()

	return out, nil
}

// Resolver resolves names in incoming ICMPResponse messages
// Everything else is passed through as is
func Resolver(input chan interface{}) (chan interface{}, error) {
	out := make(chan interface{})
	go func() {
		defer close(out)

		for val := range input {
			switch val.(type) {
			case ICMPResponse:
				resp := val.(ICMPResponse)
				names, err := net.LookupAddr(resp.fromAddr.String())
				if err != nil {
					resp.fromName = resp.fromAddr.String()
				} else {
					resp.fromName = names[0]
				}
				out <- resp
			default:
				out <- val
			}
		}
	}()
	return out, nil
}

// Sender generates TCP SYN packet probes with given TTL at given packet per second rate
// The packet descriptions are published to the output channel as Probe messages
// As a side effect, the packets are injected into raw socket
func Sender(done <-chan struct{}, srcAddr *net.IP, af, dest string, dstPort, baseSrcPort, maxSrcPorts, maxIters, ttl, pps, tos int) (chan interface{}, error) {
	var err error

	out := make(chan interface{})

	glog.V(2).Infof("Sender for ttl %d starting\n", ttl)

	dstAddr, err := resolveName(dest, af)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenPacket(af+":6", srcAddr.String())
	if err != nil {
		return nil, err
	}

	switch af {
	case "ip4":
		conn := ipv4.NewPacketConn(conn)
		if err != nil {
			return nil, err
		}
		if err := conn.SetTTL(ttl); err != nil {
			return nil, err
		}
		if err := conn.SetTOS(tos); err != nil {
			return nil, err
		}
	case "ip6":
		conn := ipv6.NewPacketConn(conn)
		if err := conn.SetHopLimit(ttl); err != nil {
			return nil, err
		}
		if err := conn.SetTrafficClass(tos); err != nil {
			return nil, err
		}
	}

	// spawn a new goroutine and return the channel to be used for reading
	go func() {
		defer conn.Close()
		defer close(out)

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
			case <-done:
				glog.V(2).Infof("Sender for ttl %d exiting prematurely\n", ttl)
				return
			}
		}
		glog.V(2).Infoln("Sender done")
	}()

	return out, nil
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
