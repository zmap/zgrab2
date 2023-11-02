package http

import (
	"reflect"
	"testing"

	"github.com/go-playground/validator/v10"
)

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

func Test_getFqdnFromLink(t *testing.T) {
	type args struct {
		v    *validator.Validate
		link string
	}
	v := validator.New()
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "empty link",
			args: args{
				v:    v,
				link: "",
			},
			want: "",
		},
		{
			name: "incorrect url",
			args: args{
				v:    v,
				link: string([]byte{0x7f}), // incorrect byte for url.Parse
			},
			want: "",
		},
		{
			name: "simple domain without scheme",
			args: args{
				v:    v,
				link: "ya.ru",
			},
			want: "",
		},
		{
			name: "simple domain with scheme",
			args: args{
				v:    v,
				link: "https://ya.ru",
			},
			want: "ya.ru",
		},
		{
			name: "ip address",
			args: args{
				v:    v,
				link: "https://1.1.1.1",
			},
			want: "",
		},
		{
			name: "single word with scheme",
			args: args{
				v:    v,
				link: "https://ya",
			},
			want: "",
		},
		{
			name: "incorrect email",
			args: args{
				v:    v,
				link: "mailto:aya.ru",
			},
			want: "",
		},
		{
			name: "incorrect fqdn in email",
			args: args{
				v:    v,
				link: "mailto:a@yaru",
			},
			want: "",
		},
		{
			name: "correct email",
			args: args{
				v:    v,
				link: "mailto:a@ya.ru",
			},
			want: "ya.ru",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getFqdnFromLink(tt.args.v, tt.args.link); got != tt.want {
				t.Errorf("getFqdnFromLink() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getUniqueFQDNFromLinks(t *testing.T) {
	type args struct {
		links []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "empty links",
			args: args{
				links: nil,
			},
			want: nil,
		},
		{
			name: "empty links",
			args: args{
				links: nil,
			},
			want: nil,
		},
		{
			name: "getFqdnFromLink return empty",
			args: args{
				links: []string{"https://ya.ru", "ya"},
			},
			want: []string{"ya.ru"},
		},
		{
			name: "non-unique links",
			args: args{
				links: []string{"https://ya.ru", "https://ya.ru"},
			},
			want: []string{"ya.ru"},
		},
		{
			name: "all links are incorrect",
			args: args{
				links: []string{"ya.ru", "ya"},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getUniqueFQDNFromLinks(tt.args.links); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getUniqueFQDNFromLinks() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseFavicon(t *testing.T) {
	type args struct {
		selectedFavicon string
	}
	//data:image/vnd.microsoft.icon;base64,
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "empty favicon",
			args: args{
				selectedFavicon: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "no ';'",
			args: args{
				selectedFavicon: "data:image/vnd.microsoft.icon",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "no ','",
			args: args{
				selectedFavicon: "data:image/vnd.microsoft.icon;base64",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "no 'base64'",
			args: args{
				selectedFavicon: "data:image/vnd.microsoft.icon;some_format,favicon",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "trimmed favicon",
			args: args{
				selectedFavicon: "data:image/vnd.microsoft.icon;base64,   \n ZmF2aWNvbg==\n \n  ",
			},
			want:    []byte("favicon"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFavicon(tt.args.selectedFavicon)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFavicon() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseFavicon() got = %v, want %v", got, tt.want)
			}
		})
	}
}
