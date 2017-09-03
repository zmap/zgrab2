all: zgrab2

.PHONY: clean zgrab2

zgrab2: 
	cd cmd/zgrab2 && go build -o zgrab2  

clean:
	go clean
