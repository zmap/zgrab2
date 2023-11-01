package http

import "testing"

func Test_selectFavicon(t *testing.T) {
	type args struct {
		favicons []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "nil favicons",
			args: args{
				favicons: nil,
			},
			want: "",
		},
		{
			name: "empty but initialized favicons",
			args: args{
				favicons: []string{},
			},
			want: "",
		},
		{
			name: "one favicon, not .ico",
			args: args{
				favicons: []string{"fav"},
			},
			want: "fav",
		},
		{
			name: "several favicon with .ico",
			args: args{
				favicons: []string{"fav1", "fav2.ico", "fav3.ico"},
			},
			want: "fav2.ico",
		},
		{
			name: "several favicon without .ico",
			args: args{
				favicons: []string{"fav1", "fav2", "fav3"},
			},
			want: "fav1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selectFavicon(tt.args.favicons); got != tt.want {
				t.Errorf("selectFavicon() = %v, want %v", got, tt.want)
			}
		})
	}
}
