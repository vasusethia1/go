package main

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "log"
    "net"
    "strings"
    "io"
    "sync"
    "bytes"
    "os/exec"
    "encoding/hex"
)
const (
    CONN_HOST = "0.0.0.0"
    CONN_PORT = "4444"
    CONN_TYPE = "tcp"
)
var wg sync.WaitGroup
var flag bool
var client_id string
var port_number string
var flag1 int
const (
    srvAddr         = "224.0.0.1:9999"
    maxDatagramSize = 8192
)

func main() {
    
    flag1=0
    reply := make([]byte,256)
    cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
    if err != nil {
        log.Fatalf("server: loadkeys: %s", err)
    }
    config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
    conn, err := tls.Dial("tcp", "10.1.37.96:8000", &config)
    if err != nil {
        log.Fatalf("client: dial: %s", err)
    }
    log.Println("client: connected to: ", conn.RemoteAddr())
    state := conn.ConnectionState()
    for _, v := range state.PeerCertificates {
        fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
        fmt.Println(v.Subject)
    }
    log.Println("client: handshake: ", state.HandshakeComplete)
    log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)
    message := "SYN"
    fmt.Println("Sending SYN packet")
    _,err = io.WriteString(conn, message)
    if err != nil {
        log.Fatalf("client: write: %s", err)
    }
    c := make(chan string)
    if err != nil {
        fmt.Println("Error")
    }
    if flag == true {
        message = "ERR " + client_id
        fmt.Println("Sending ERR packet") 
        _,err = io.WriteString(conn,message)
        if err != nil {
            fmt.Println("Unable to write to the network")
            return
        }
        message = "RESCAN " + port_number
        fmt.Println("Sending RESCAN packet")
        _,err = io.WriteString(conn,message)
        if err != nil {
            fmt.Println("Unable to send the RESCAN request")
            return
        }
        netData,err := conn.Read(reply)
        if err != nil {
            fmt.Println("Error reading the network")
            return
        }
        temp :=  strings.TrimSpace(string(reply[:netData]))
        if strings.Contains(temp,"SCAN") {
            fmt.Println("SCAN packet received")
            fmt.Println("Scanning 0.0.0.0 for port :"+temp[4:])
            port_number= temp[5:]
            wg.Add(1)
            go StartScanZmap(conn)
            wg.Wait()
        }
    }
    wg.Add(1)
    go StartTransaction(conn,c)
    wg.Wait()
}
func StartTransaction(conn net.Conn,c chan string) {
        reply := make([]byte,256)
        for {
            if flag1 == 1 {
                message := "SYN"
                fmt.Println("Sending SYN packet")
                _,err := io.WriteString(conn,message)
                if err != nil {
                    fmt.Println("Unable to send RESYN packet")
                }
                flag1=0
            }
            netData, err := conn.Read(reply)
            if err != nil {
                fmt.Println(err)
                return
            }
            temp :=  strings.TrimSpace(string(reply[:netData]))
            if strings.Contains(temp,"ACK ID") {
                client_id = temp[7:]
                fmt.Println("Client ID assigned sending START request"+ client_id)
                conn.Write([]byte("START REQ"))
            }
            if strings.Contains(temp,"SCAN") {
                fmt.Println("Scanning 0.0.0.0 for port :"+temp[4:])
		port_number=temp[5:]
                StartScanZmap(conn)
                flag1=1
                //c <- temp[5:]
                //port_number = <-c
            }
        }
    wg.Done()
}
func StartScanZmap(conn net.Conn){
    fmt.Println(port_number) 
    cmd := exec.Command("sudo","python","/opt/cmdexec.py",port_number)
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr
    fmt.Println(cmd)
    err := cmd.Run()
    if err != nil {
        log.Fatalf("cmd.Run() failed with %s\n", err)
        flag = true
        main()

    }
    outStr, errStr := string(stdout.Bytes()), string(stderr.Bytes())
    fmt.Printf("out:\n%s\nerr:\n%s\n", outStr, errStr) 
    _,err = io.WriteString(conn,"DONE "+client_id)
    fmt.Println("Sending DONE packet")
    if err != nil {
        fmt.Println("Failed to send DONE packet")
        return
    }
    fmt.Println("Listening for broadcast message")
    serveMulticastUDP(srvAddr, msgHandler)
}
func msgHandler(src *net.UDPAddr, n int, b []byte) {
    log.Println(n, "bytes read from", src)
    log.Println(hex.Dump(b[:n]))
}
func serveMulticastUDP(a string, h func(*net.UDPAddr, int, []byte)) {
    addr, err := net.ResolveUDPAddr("udp", a)
    if err != nil {
        log.Fatal(err)
    }
    l, err := net.ListenMulticastUDP("udp", nil, addr)
    l.SetReadBuffer(maxDatagramSize)
    b := make([]byte, maxDatagramSize)
    n, src, err := l.ReadFromUDP(b)
    if err != nil {
        log.Fatal("ReadFromUDP failed:", err)
    }
    h(src, n, b)
    l.Close()
    return
}