package main

import (
	"log"
	"os"
	"errors"
	"net"
	"bytes"
	"io"
	"fmt"
	"encoding/binary"
)

const (
	DmapPacketBodySize = 65520
	DmapPacketMagic = 0xCBEECBEE
	DmapKeySize = 16
	DmapValueSize = 4096
	DmapPacketSetKey = 1
	DmapPacketGetKey = 2
	DmapPacketDelKey = 3
)

type DmapPacketHeader struct {
	Magic uint32
	Type uint32
	Len uint32
	Result uint32
}

type DmapPacket struct {
	Header DmapPacketHeader
	Body []byte
}

type DmapToBytes interface {
	ToBytes() ([]byte, error)
}

type DmapParseBytes interface {
	ParseBytes(body []byte) error
}

type DmapReqSetKey struct {
	Key [DmapKeySize]byte
	Value [DmapValueSize]byte
}

type DmapRespSetKey struct {
	Padding uint64
}

type DmapReqGetKey struct {
	Key [DmapKeySize]byte
}

type DmapRespGetKey struct {
	Value [DmapValueSize]byte
}

type DmapReqDelKey struct {
	Key [DmapKeySize]byte
}

type DmapRespDelKey struct {
	Padding uint64
}

func (req *DmapReqSetKey) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, req)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (resp *DmapRespSetKey) ParseBytes(body []byte) error {
	err := binary.Read(bytes.NewReader(body), binary.LittleEndian, resp)
	if err != nil {
		return err
	}
	return nil
}

func (req *DmapReqGetKey) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, req)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (resp *DmapRespGetKey) ParseBytes(body []byte) error {
	err := binary.Read(bytes.NewReader(body), binary.LittleEndian, resp)
	if err != nil {
		return err
	}
	return nil
}

func (req *DmapReqDelKey) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, req)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (resp *DmapRespDelKey) ParseBytes(body []byte) error {
	err := binary.Read(bytes.NewReader(body), binary.LittleEndian, resp)
	if err != nil {
		return err
	}
	return nil
}



func Usage(rc int) {
	log.Printf("Usage:\n")
	log.Printf("dmap-client <host:ip> <set> <key> <value>\n")
	log.Printf("dmap-client <host:ip> <get> <key>\n")
	log.Printf("dmap-client <host:ip> <del> <key>\n")
	os.Exit(rc)
}

type Client struct {
	Host string
	Con net.Conn
}

func (client *Client) Init(host string) {
	client.Host = host
}

func (client *Client) Dial() error {
	con, err := net.Dial("tcp", client.Host)
	if err != nil {
		return err
	}
	client.Con = con
	return nil
}

func (client *Client) CreatePacket(packetType uint32, body []byte) *DmapPacket {
	packet := new(DmapPacket)
	packet.Header.Magic = DmapPacketMagic
	packet.Header.Type = packetType
	packet.Header.Len = uint32(len(body))
	packet.Header.Result = 0
	packet.Body = body
	return packet
}

func (client *Client) SendPacket(packet *DmapPacket) error {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, &packet.Header)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.LittleEndian, packet.Body)
	if err != nil {
		return err
	}

	n, err := client.Con.Write(buf.Bytes())
	if err != nil {
		return err
	}

	if n != buf.Len() {
		return errors.New("Incomplete I/O")
	}

	return nil
}

func (client *Client) RecvPacket() (*DmapPacket, error) {
	packet := new(DmapPacket)
	err := binary.Read(client.Con, binary.LittleEndian, &packet.Header)
	if err != nil {
		return nil, err
	}

	if packet.Header.Magic != DmapPacketMagic {
		return nil, errors.New("Invalid packet magic")
	}

	if packet.Header.Len > DmapPacketBodySize {
		return nil, errors.New("Packet body len too big")
	}

	body := make([]byte, packet.Header.Len)
	if packet.Header.Len != 0 {
		body := make([]byte, packet.Header.Len)
		n, err := io.ReadFull(client.Con, body)
		if err != nil {
			return nil, err
		}

		if uint32(n) != packet.Header.Len {
			return nil, errors.New("Incomplete I/O")
		}
	}
	packet.Body = body

	return packet, nil
}

func (client *Client) MakePacket(req DmapToBytes) (*DmapPacket, error) {
	body, err := req.ToBytes()
	if err != nil {
		return nil, err
	}
	return client.CreatePacket(DmapPacketSetKey, body), nil
}

func (client *Client) SendRequest(req DmapToBytes) error {
	packet, err := client.MakePacket(req)
	if err != nil {
		return err
	}

	return client.SendPacket(packet)
}

func (client *Client) RecvResponse(resp DmapParseBytes) error {
	packet, err := client.RecvPacket()
	if err != nil {
		return err
	}

	if packet.Header.Result != 0 {
		return fmt.Errorf("Packet error: %d", int32(packet.Header.Result))
	}

	return resp.ParseBytes(packet.Body)
}

func (client *Client) SendRecv(req DmapToBytes, resp DmapParseBytes) error {
	err := client.SendRequest(req)
	if err != nil {
		return err
	}

	err = client.RecvResponse(resp)
	if err != nil {
		return err
	}

	return nil
}

func (client *Client) SetKey(key string, value string) error {
	req := new(DmapReqSetKey)
	resp := new(DmapRespSetKey)

	keyBytes := []byte(key)
	valueBytes := []byte(value)

	if len(keyBytes) > len(req.Key) {
		return errors.New("Key too big")
	}

	if len(valueBytes) > len(req.Value) {
		return errors.New("Value too big")
	}

	copy(req.Key[:len(req.Key)], keyBytes)
	copy(req.Value[:len(req.Value)], valueBytes)


	err := client.SendRecv(req, resp)
	if err != nil {
		return err
	}

	return nil
}

func (client *Client) GetKey(key string) (string, error) {
	req := new(DmapReqGetKey)
	resp := new(DmapRespGetKey)

	keyBytes := []byte(key)
	if len(keyBytes) > len(req.Key) {
		return "", errors.New("Key too big")
	}

	copy(req.Key[:len(req.Key)], keyBytes)

	err := client.SendRecv(req, resp)
	if err != nil {
		return "", err
	}

	return string(resp.Value[:len(resp.Value)]), nil
}

func (client *Client) DelKey(key string) error {
	req := new(DmapReqDelKey)
	resp := new(DmapRespDelKey)

	keyBytes := []byte(key)
	if len(keyBytes) > len(req.Key) {
		return errors.New("Key too big")
	}

	copy(req.Key[:len(req.Key)], keyBytes)

	err := client.SendRecv(req, resp)
	if err != nil {
		return err
	}

	return nil
}

func (client *Client) Close() {
	if client.Con != nil {
		client.Con.Close()
	}
}

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	if len(os.Args) < 3 {
		Usage(1)
		return
	}

	host := os.Args[1]
	cmd := os.Args[2]

	client := new(Client)
	client.Init(host)

	if cmd == "set" {
		if len(os.Args) != 5 {
			Usage(1)
			return
		}
		key := os.Args[3]
		value := os.Args[4]
		err := client.Dial()
		if err != nil {
			log.Printf("Dial failed: %v", err)
			os.Exit(1)
			return
		}
		defer client.Close()
		err = client.SetKey(key, value)
		if err != nil {
			log.Printf("Set key failed: %v", err)
			os.Exit(1)
			return
		}
	} else if cmd == "get" {
		if len(os.Args) != 4 {
			Usage(1)
			return
		}
		key := os.Args[3]
		err := client.Dial()
		if err != nil {
			log.Printf("Dial failed: %v", err)
			os.Exit(1)
			return
		}
		defer client.Close()
		value, err := client.GetKey(key)
		if err != nil {
			log.Printf("Get key failed: %v", err)
			os.Exit(1)
			return
		}
		log.Printf("%s", value)
	} else if cmd == "del" {
		if len(os.Args) != 4 {
			Usage(1)
			return
		}
		key := os.Args[3]
		err := client.Dial()
		if err != nil {
			log.Printf("Dial failed: %v", err)
			os.Exit(1)
			return
		}
		defer client.Close()
		err = client.DelKey(key)
		if err != nil {
			log.Printf("Delete key failed: %v", err)
			os.Exit(1)
			return
		}
	} else {
		Usage(1)
		return
	}
	os.Exit(0)
	return
}
