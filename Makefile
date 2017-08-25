all: zgrab2

.PHONY: clean zgrab2

zgrab2: 
	cd main && go build -o zgrab2 

clean:
	go clean
