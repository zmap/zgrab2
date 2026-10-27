package mongodb

import "testing"

func TestFlagsValidate(t *testing.T) {
	tests := []struct {
		name    string
		flags   Flags
		wantErr bool
	}{
		{name: "plaintext"},
		{name: "TLS", flags: Flags{UseTLS: true}},
		{name: "TLS with downgrade", flags: Flags{UseTLS: true, AllowTLSDowngrade: true}},
		{name: "downgrade without TLS", flags: Flags{AllowTLSDowngrade: true}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.flags.Validate(nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
