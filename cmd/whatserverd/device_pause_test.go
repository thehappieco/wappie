package main

import (
	"go.mau.fi/whatsmeow/types"
	"testing"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func TestPausedDeviceSurvivesRestartWithoutReconnect(t *testing.T) {
	device := store.Device{ID: "paused", Status: wa.StatusOnline, Paused: true, Identity: wa.Identity{PN: types.JID{User: "15551234567", Server: types.DefaultUserServer}}}
	if shouldResume(device) {
		t.Fatal("paused device would restart")
	}
	if len(needsClaim([]store.Device{device}, nil)) != 0 {
		t.Fatal("supervisor would undo explicit pause")
	}
	device.Paused = false
	if !shouldResume(device) {
		t.Fatal("resumed device remains blocked")
	}
}
