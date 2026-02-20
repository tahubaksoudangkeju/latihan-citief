package main

import (
    "fmt"
    "os"
    "io/ioutil"
)

const S0 byte = 0x5a
var PHI = []byte{7, 11, 18, 29, 47, 76, 123}

func rotl8(x byte, r int) byte {
    r &= 7
    return ((x << r) | (x >> (8 - r)))
}

func encLite(data []byte) []byte {
    s := S0
    out := make([]byte, 0, len(data)+1)
    out = append(out, s)
    for i := 0; i < len(data); i++ {
        k := rotl8(s, i%8)
        c := ((data[i] + s) & 0xFF) ^ k
        out = append(out, c)
        s = (s + c + PHI[i%len(PHI)]) & 0xFF
    }
    return out
}

func main() {
    if len(os.Args) < 3 {
        fmt.Printf("Usage: %s flag.txt encrypted.bin\n", os.Args[0])
        return
    }
    b, _ := ioutil.ReadFile(os.Args[1])
    for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') { b = b[:len(b)-1] }
    ct := encLite(b)
    ioutil.WriteFile(os.Args[2], ct, 0644)
}
