package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxDNSMessageBytes = 4 << 10
	dnsResponseTTL     = 30
	dnsIOTimeout       = 5 * time.Second
)

func (s *Server) serveDNSUDP(ctx context.Context, connection net.PacketConn) error {
	buffer := make([]byte, maxDNSMessageBytes+1)
	for {
		n, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if n > maxDNSMessageBytes {
			continue
		}
		response, ok := s.dnsResponse(buffer[:n])
		if !ok || len(response) > maxDNSMessageBytes {
			continue
		}
		if _, err := connection.WriteTo(response, peer); err != nil {
			return err
		}
	}
}

func (s *Server) serveDNSTCP(ctx context.Context, listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.handleDNSTCP(ctx, connection)
	}
}

func (s *Server) handleDNSTCP(ctx context.Context, connection net.Conn) {
	defer connection.Close()
	deadline := time.Now().Add(dnsIOTimeout)
	if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	_ = connection.SetDeadline(deadline)
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection, header); err != nil {
		return
	}
	length := int(binary.BigEndian.Uint16(header))
	if length == 0 || length > maxDNSMessageBytes {
		return
	}
	request := make([]byte, length)
	if _, err := io.ReadFull(connection, request); err != nil || ctx.Err() != nil {
		return
	}
	response, ok := s.dnsResponse(request)
	if !ok || len(response) > maxDNSMessageBytes {
		return
	}
	binary.BigEndian.PutUint16(header, uint16(len(response)))
	_ = writeFull(connection, append(header, response...))
}

func (s *Server) dnsResponse(request []byte) ([]byte, bool) {
	var parser dnsmessage.Parser
	header, err := parser.Start(request)
	if err != nil || header.Response || header.OpCode != 0 {
		return nil, false
	}
	question, err := parser.Question()
	if err != nil {
		return s.buildDNSResponse(header, dnsmessage.Question{}, dnsmessage.RCodeFormatError, false)
	}
	if _, err := parser.Question(); !errors.Is(err, dnsmessage.ErrSectionDone) ||
		!sectionEmpty(parser.AnswerHeader) || !sectionEmpty(parser.AuthorityHeader) || !validAdditionalSection(&parser) {
		return s.buildDNSResponse(header, question, dnsmessage.RCodeFormatError, false)
	}
	allowed := question.Class == dnsmessage.ClassINET &&
		(question.Type == dnsmessage.TypeA || question.Type == dnsmessage.TypeAAAA) &&
		s.config.Policy.Allows(question.Name.String())
	if !allowed {
		return s.buildDNSResponse(header, question, dnsmessage.RCodeRefused, false)
	}
	return s.buildDNSResponse(header, question, dnsmessage.RCodeSuccess, question.Type == dnsmessage.TypeA)
}

func validAdditionalSection(parser *dnsmessage.Parser) bool {
	header, err := parser.AdditionalHeader()
	if errors.Is(err, dnsmessage.ErrSectionDone) {
		return true
	}
	if err != nil || header.Type != dnsmessage.TypeOPT || header.Name.String() != "." ||
		uint16(header.Class) < 512 || uint16(header.Class) > maxDNSMessageBytes ||
		header.TTL & ^uint32(0x8000) != 0 {
		return false
	}
	if _, err := parser.OPTResource(); err != nil {
		return false
	}
	return sectionEmpty(parser.AdditionalHeader)
}

func sectionEmpty(next func() (dnsmessage.ResourceHeader, error)) bool {
	_, err := next()
	return errors.Is(err, dnsmessage.ErrSectionDone)
}

func (s *Server) buildDNSResponse(request dnsmessage.Header, question dnsmessage.Question, responseCode dnsmessage.RCode, answer bool) ([]byte, bool) {
	header := dnsmessage.Header{
		ID: request.ID, Response: true, OpCode: request.OpCode,
		Authoritative: true, RecursionDesired: request.RecursionDesired,
		RecursionAvailable: false, RCode: responseCode,
	}
	builder := dnsmessage.NewBuilder(nil, header)
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, false
	}
	if question.Name.Length != 0 {
		if err := builder.Question(question); err != nil {
			return nil, false
		}
	}
	if answer {
		address := net.ParseIP(s.config.GatewayAddress).To4()
		if len(address) != net.IPv4len || builder.StartAnswers() != nil {
			return nil, false
		}
		var value [4]byte
		copy(value[:], address)
		if err := builder.AResource(dnsmessage.ResourceHeader{
			Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: dnsResponseTTL,
		}, dnsmessage.AResource{A: value}); err != nil {
			return nil, false
		}
	}
	response, err := builder.Finish()
	return response, err == nil
}
