package wa_test

import (
	"context"
	"errors"
	"testing"
	"whatserver2/internal/wa"
	"whatserver2/internal/wa/fakewa"
)

func TestColdConnectChecksPolicyAgainAfterFailure(t *testing.T) {
	fake := fakewa.New()
	denied := errors.New("storage paused")
	checks := 0
	dev, err := wa.NewDevice(wa.DeviceConfig{ID: "device", TenantID: "tenant", Client: fake, CheckStart: func(context.Context, string) error {
		checks++
		if checks == 2 {
			return denied
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	fake.ConnectErr = errors.New("offline")
	if err = dev.Start(context.Background()); !errors.Is(err, denied) {
		t.Fatalf("got %v", err)
	}
	if checks != 2 {
		t.Fatalf("checks %d", checks)
	}
}
