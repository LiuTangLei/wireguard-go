module github.com/LiuTangLei/wireguard-go/tsasm/amd64/chacha20poly1305/_asm

go 1.26.0

require github.com/mmcloughlin/avo v0.6.0

require golang.org/x/crypto v0.54.0 // indirect

require (
	github.com/LiuTangLei/wireguard-go v0.0.0
	golang.org/x/mod v0.39.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
)

replace github.com/LiuTangLei/wireguard-go => ../../../..
