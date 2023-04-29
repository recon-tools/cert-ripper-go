package host

import "testing"

func TestValidHostname(t *testing.T) {
	hostname := "google.com"
	res := IsValidHostname(hostname)
	if !res {
		t.Errorf("IsValidHostname(%s) = %t; want true", hostname, res)
	}
}

func TestInValidHostname(t *testing.T) {
	hostname := "google@asd"
	res := IsValidHostname(hostname)
	if res {
		t.Errorf("IsValidHostname(%s) = %t; want false", hostname, res)
	}

	hostname2 := "https://google.com"
	res2 := IsValidHostname(hostname)
	if res {
		t.Errorf("IsValidHostname(%s) = %t; want false", hostname2, res2)
	}
}
