all: zgrab2

.PHONY: clean zgrab2

zgrab2: 
	cd main && go build -o zgrab2 && ./zgrab2 multiple -c mult.ini 

clean:
	go clean
