package main

/*

This file is an implementation of draft-shore-tls-dnssec-chain-extension-00.
In the long run, it should probably be published as a library, or folded into
the Go TLS stack.  For now, however, it is just a runnable Go file:

> go run tls-dnssec-00.go

*/

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// An RRset structure represents a signed sets of DNS resource records,
// together with the corresponding RRSIG record
type RRset struct {
	Type  uint16 // For convenience only, not serialized
	RRs   []dns.RR
	RRSIG *dns.RRSIG
}

func (rrs RRset) String() string {
	ret := "rrs:\n"
	for _, rr := range rrs.RRs {
		ret += fmt.Sprintf("  %s\n", rr.String())
	}
	ret += fmt.Sprintf("rrsig: %s\n", rrs.RRSIG.String())
	return ret
}

// Marshal renders an RRset using the TLS syntax defined in
// draft-shore-tls-dnssec-chain-extension-00
//
// struct {
//   opaque rrset<0..2^16-1>;
//   opaque rrsig<0..2^16-1>;
// } RRset
func (rrs RRset) Marshal() ([]byte, error) {
	// XXX Ideally, we would do what rawSignatureData does in dnssec.go
	//     However, that method relies on private functions.  So instead,
	//     we make a giant buffer and do a rolling pack into it.  PackRR
	//     will return an error if we overflow it.
	//
	// XXX Also, we only do basic c14n here, case-folding the owner name.
	data := make([]byte, 1<<20)

	off := 2
	var err error
	for i := range rrs.RRs {
		rrs.RRs[i].Header().Name = strings.ToLower(rrs.RRs[i].Header().Name)
		off, err = dns.PackRR(rrs.RRs[i], data, off, nil, false)
		if err != nil {
			return nil, err
		}
	}

	rrsetLength := off - 2
	data[0] = byte(rrsetLength >> 8)
	data[1] = byte(rrsetLength & 0xFF)

	rrsigLengthOff := off
	off, err = dns.PackRR(rrs.RRSIG, data, off+2, nil, false)
	if err != nil {
		return nil, err
	}

	rrsigLength := off - rrsetLength - 2 - 2
	data[rrsigLengthOff] = byte(rrsigLength >> 8)
	data[rrsigLengthOff+1] = byte(rrsigLength & 0xFF)

	return data[:off], nil
}

// UnmarshalRRset parses the TLS syntax described in
// draft-shore-tls-dnssec-chain-extension-00, starting at offset `off`.
// It returns the parsed RRset and the offset immediately after this
// RRset, i.e., the offset where you should start parsing the next thing.
func UnmarshalRRset(data []byte, off int) (RRset, int, error) {
	rrs := RRset{}
	off1 := off

	if len(data) < off+4 {
		return rrs, off1, fmt.Errorf("Not enough bytes")
	}

	rrsetLength := (int(data[off]) << 8) + int(data[off+1])
	if rrsetLength > len(data)-off-4 {
		return rrs, off1, fmt.Errorf("nonsensical RRset length")
	}

	rrsigLength := (int(data[off+2+rrsetLength]) << 8) + int(data[off+2+rrsetLength+1])
	if off+2+rrsetLength+2+rrsigLength > len(data) {
		return rrs, off1, fmt.Errorf("nonsensical RRSIG length")
	}

	rrs.RRs = []dns.RR{}
	rrOff := off + 2
	var rr dns.RR
	var err error
	for rrOff < off+2+rrsetLength {
		rr, rrOff, err = dns.UnpackRR(data, rrOff)
		if err != nil {
			return rrs, off1, err
		}

		rrs.RRs = append(rrs.RRs, rr)
	}
	if rrOff != off+2+rrsetLength {
		return rrs, off1, fmt.Errorf("RRset decoded length did not match declared length")
	}

	rrsigOff := off + 2 + rrsetLength + 2
	rrsig, rrsigOff, err := dns.UnpackRR(data, rrsigOff)
	if err != nil {
		return rrs, off1, err
	}
	if rrsigOff != off+2+rrsetLength+2+rrsigLength {
		return rrs, off1, fmt.Errorf("RRSIG decoded length did not match declared length %d != %d",
			rrsigOff, off+2+rrsetLength+2+rrsigLength)

	}
	if _, ok := rrsig.(*dns.RRSIG); !ok {
		return rrs, off1, fmt.Errorf("RRSIG decoded as something other than an RRSIG")
	}

	rrs.RRSIG = rrsig.(*dns.RRSIG)
	rrs.Type = rrs.RRSIG.TypeCovered
	off1 = off + 2 + rrsetLength + 2 + rrsigLength
	return rrs, off1, nil
}

func (rrs RRset) dnskeyWithTag(tag uint16) *dns.DNSKEY {
	for _, rr := range rrs.RRs {
		key, ok := rr.(*dns.DNSKEY)
		if !ok {
			return nil
		}
		if key.KeyTag() == tag {
			return key
		}
	}
	return nil
}

func (rrs RRset) dsWithTag(tag uint16) *dns.DS {
	for _, rr := range rrs.RRs {
		key, ok := rr.(*dns.DS)
		if !ok {
			return nil
		}
		if key.KeyTag == tag {
			return key
		}
	}
	return nil
}

// An AuthenticationChain structure represents an authentication chain,
// in the format defined by draft-shore-tls-dnssec-chain-extension-00.
// Syntactically, it is just sequence of RRsets, but it is subject to the
// rules specified in that document.
type AuthenticationChain []RRset

// Marshal renders an authentication chain to a vector of RRset objects
// using the TLS vector syntax.
func (ac AuthenticationChain) Marshal() ([]byte, error) {
	length := uint16(len(ac))
	data := []byte{
		byte(length >> 8),
		byte(length & 0xFF),
	}

	for _, rrs := range ac {
		rrsetData, err := rrs.Marshal()
		if err != nil {
			return nil, err
		}

		data = append(data, rrsetData...)
	}

	return data, nil
}

// UnmarshalAuthenticationChain parses the TLS vector syntax, starting at
// offset `off`, to recover the encoded sequence of RRsets.
// It returns the parsed AuthenticationChain and the offset immediately
// after it, i.e., the offset where you should start parsing the next thing.
func UnmarshalAuthenticationChain(data []byte, off int) (AuthenticationChain, int, error) {
	ac := AuthenticationChain{}

	if len(data) < off+2 {
		return nil, off, fmt.Errorf("Not enough bytes")
	}

	nRRsets := (int(data[off]) << 8) + int(data[off+1])
	rrsetOff := off + 2
	var rrset RRset
	var err error
	for len(ac) < nRRsets {
		rrset, rrsetOff, err = UnmarshalRRset(data, rrsetOff)
		if err != nil {
			return nil, off, err
		}

		ac = append(ac, rrset)
	}

	return ac, rrsetOff, nil
}

func findKeyInList(tag uint16, keys []*dns.DNSKEY) *dns.DNSKEY {
	for _, dnskey := range keys {
		if dnskey.KeyTag() == tag {
			return dnskey
		}
	}
	return nil
}

// Verify applies DNSSEC verification logic to the proposed authentication
// chain.  If all of the checks pass, then it returns nil; otherwise it
// returns an error describing what went wrong.
func (ac AuthenticationChain) Verify(trustAnchors []*dns.DNSKEY) error {
	for i, rrset := range ac {
		if i == len(ac)-1 {
			break
		}

		next := ac[i+1]

		if rrset.RRSIG == nil {
			// If we hit a nil RRSIG, then something has gone wrong.  The only
			// way a nil RRSIG is valid is if it is on a DNSKEY RRset containing
			// a trust anchor.  In that case, we will have already returned success
			// on validating the signature on the previous RRset.
			return fmt.Errorf("nil RRSIG on non-trust-anchor")
		} else if rrset.Type == dns.TypeDNSKEY && next.Type == dns.TypeDS {
			// Check for match between signing DNSKEY and DS
			key := rrset.dnskeyWithTag(rrset.RRSIG.KeyTag)
			if key == nil {
				return fmt.Errorf("Unable to find DNSKEY record with key tag %d", rrset.RRSIG.KeyTag)
			}

			ds := next.dsWithTag(rrset.RRSIG.KeyTag)
			if ds == nil {
				return fmt.Errorf("Unable to find DS record with key tag %d", rrset.RRSIG.KeyTag)
			}

			err := rrset.RRSIG.Verify(key, rrset.RRs)
			if err != nil {
				return err
			}

			keyDS := key.ToDS(ds.DigestType)
			if ds.Digest != keyDS.Digest {
				return fmt.Errorf("DS does not match signing DNSKEY")
			}
		} else if next.Type == dns.TypeDNSKEY {
			// Check signature with DNSKEY from next RRset
			key := next.dnskeyWithTag(rrset.RRSIG.KeyTag)
			if key == nil {
				return fmt.Errorf("Unable to find DNSKEY record with key tag %d", rrset.RRSIG.KeyTag)
			}

			err := rrset.RRSIG.Verify(key, rrset.RRs)
			if err != nil {
				return err
			}

			// If the signing key is a trust anchor, we're done!
			ta := findKeyInList(key.KeyTag(), trustAnchors)
			if ta != nil {
				return nil
			}
		} else {
			return fmt.Errorf("Invalid sequence of RRsets")
		}

		// TODO Check non-cryptographic properties
	}

	// If we haven't seen a trust anchor by now, the final RRset must
	// be signed by a trust anchor
	finalRRset := ac[len(ac)-1]
	key := findKeyInList(finalRRset.RRSIG.KeyTag, trustAnchors)
	if key == nil {
		return fmt.Errorf("Terminal DS not signed by a trust anchor")
	}

	err := finalRRset.RRSIG.Verify(key, finalRRset.RRs)
	if err != nil {
		return err
	}

	return nil
}

//////////

func fetch(name string, rrtype uint16) ([]dns.RR, *dns.RRSIG, error) {
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.SetEdns0(4096, true) // Set DO bit
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{Name: name, Qtype: rrtype, Qclass: dns.ClassINET}

	c := new(dns.Client)
	in, _, err := c.Exchange(m1, "8.8.8.8:53")
	if err != nil {
		return nil, nil, err
	}

	rrset := []dns.RR{}
	var rrsig *dns.RRSIG
	for _, rr := range in.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			rrsig = rr.(*dns.RRSIG)
		} else {
			rrset = append(rrset, rr)
		}
	}

	return rrset, rrsig, err
}

// GatherAuthenticationChain fetches the DNS records necessary for an
// an authentication chain.  It starts from the specified target RR, and
// proceeds up the tree, chaining based on the signer name in RRSIG records.
// It stops when it reaches the root, or an unsigned RRset.
func GatherAuthenticationChain(name string, rrtype uint16) (AuthenticationChain, error) {
	ac := AuthenticationChain{}

	rrset, rrsig, err := fetch(name, rrtype)
	if err != nil {
		return nil, err
	} else if rrsig == nil {
		return nil, fmt.Errorf("No RRSIG provided")
	}
	ac = append(ac, RRset{RRs: rrset, RRSIG: rrsig, Type: rrsig.TypeCovered})

	// Chain up until we hit a non-signed record, or the root
	currName := rrsig.SignerName
	wasNonDNSKEY := true
	for currName != "." {
		// Try to find the next level up of DNSKEY records
		rrset, rrsig, err := fetch(currName, dns.TypeDNSKEY)
		if err != nil {
			return nil, err
		} else if rrsig == nil {
			ac = append(ac, RRset{
				RRs:   rrset,
				RRSIG: rrsig,
				Type:  rrset[0].Header().Rrtype,
			})
			break
		}

		// If that doesn't work, try DS
		if rrsig.SignerName != currName || wasNonDNSKEY {
			ac = append(ac, RRset{RRs: rrset, RRSIG: rrsig, Type: rrsig.TypeCovered})
			currName = rrsig.SignerName
			wasNonDNSKEY = false
		} else {
			rrset, rrsig, err := fetch(currName, dns.TypeDS)
			if err != nil {
				return nil, err
			} else if rrsig == nil {
				ac = append(ac, RRset{
					RRs:   rrset,
					RRSIG: rrsig,
					Type:  rrset[0].Header().Rrtype,
				})
				break
			}

			ac = append(ac, RRset{RRs: rrset, RRSIG: rrsig})
			currName = rrsig.SignerName // which better be different
			wasNonDNSKEY = true
		}
	}

	// If we got to the root, append the root ZSK RRset
	if currName == "." {
		rrset, rrsig, err := fetch(".", dns.TypeDNSKEY)
		if err != nil {
			return nil, err
		}
		ac = append(ac, RRset{RRs: rrset, RRSIG: rrsig})
	}

	// XXX We should probably check that the chain verifies (with
	// some TA) before we return it.
	return ac, nil
}

//////////

// Below this line is sample code, not suitable for a library

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

var rootKSK = []string{
	". 8179 IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=",
}

func trustAnchorsFromPresentation(rrs []string) []*dns.DNSKEY {
	tas := make([]*dns.DNSKEY, len(rrs))
	for i, zsk := range rrs {
		rr, err := dns.NewRR(zsk)
		panicOnError(err)

		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			panic("Failed to cast to *dns.DNSKEY")
		}

		tas[i] = dnskey
	}
	return tas
}

func main() {
	targetName := "www.cia.gov."
	targetType := dns.TypeCNAME
	trustAnchors := trustAnchorsFromPresentation(rootKSK)

	ac, err := GatherAuthenticationChain(targetName, targetType)
	panicOnError(err)

	// Estimate the size of a cert chain as one 2x2048-bit signature
	// for each DNSKEY record, plus a 50% overhead.  This may still
	// slightly undercount.
	estCertChainSize := 0
	estCertSize := 768
	for _, rrs := range ac {
		if rrs.Type == dns.TypeDNSKEY {
			estCertChainSize += estCertSize
		}
	}

	// Serialize the chain
	acData, err := ac.Marshal()
	panicOnError(err)

	// Deserialize the chain
	acParsed, _, err := UnmarshalAuthenticationChain(acData, 0)
	panicOnError(err)

	// See if it still verifies after the round-trip
	err = acParsed.Verify(trustAnchors)

	// Print out a summary:
	separator := "\n==========\n"
	fmt.Println(separator)
	fmt.Println("Gathered authentication chain:")
	for _, rrset := range ac {
		fmt.Println(rrset)
	}
	fmt.Println()

	fmt.Println(separator)
	fmt.Printf("Authentication chain serializes to %d octets:\n", len(acData))
	fmt.Printf("A comparable cert chain would be roughly %d octets.\n", estCertChainSize)
	fmt.Println()
	fmt.Println("Serialized authentication chain:")
	fmt.Println(hex.EncodeToString(acData))

	fmt.Println(separator)
	if err != nil {
		fmt.Println("Error verifying: ", err)
	} else {
		fmt.Println("Verified successfully")
	}
	fmt.Println()
}
