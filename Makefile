all: zgrab2/zgrab2

zgrab2/zgrab2: 
	cd main && go build -o zgrab2
