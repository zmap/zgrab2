package main

import (
    "os"

    "gopkg.in/alecthomas/kingpin.v2"
)

var (
    zgrab = kingpin.New("zgrab", "Banner Grabber")
    outputFile = zgrab.Flag("output-file", "Output filename, use - for stdout").Default("-").String()
    inputFile = zgrab.Flag("input-file", "Input filename, use - for stdin").Default("-").String()
    metadataFile = zgrab.Flag("metadata-file", "File to record banner-grab metadata, use - for stdout").Default("-").String()
    logFile = zgrab.Flag("log-file", "File to log to, use - for stderr").Default("-").String()
    

    ssh = zgrab.Command("ssh", "SSH scan")
    sshClient = ssh.Arg("ssh-client", "Mimic behavior of a specific SSH client").String()
    sshHostKeyAlgorithms = ssh.Arg("ssh-host-key-algorithms", "Set SSH Host Key Algorithms").String()
    sshKexAlgorithms = ssh.Arg("ssh-key-algorithms", "Set SSH Key Exchange Algorithms").String()
    tls = zgrab.Command("tls", "TLS scan")
    http = zgrab.Command("http", "HTTP scan")
    ftp = zgrab.Command("ftp", "FTP scan")
)

func main() {
    switch kingpin.MustParse(zgrab.Parse(os.Args[1:])) {
        case ssh.FullCommand():
            println("ssh scan")
        case tls.FullCommand():
            println("tls scan")
        case http.FullCommand():
            println("http scan")
        case ftp.FullCommand():
            println("ftp scan")
    }
}
