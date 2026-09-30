package router

import (
	"context"
	"github.com/xxx-holic/wishtoken-desktop/internal/basispoints"
	"testing"
)

func TestNativeKeepsExplicitServiceTier(t *testing.T) {
	for _, tier := range []string{"priority", "default", "fast"} {
		body := object{"service_tier": tier, "temperature": 0.5}
		stripNativeUnsupported(body)
		if body["service_tier"] != tier {
			t.Fatal("speed request was silently dropped")
		}
		if _, found := body["temperature"]; found {
			t.Fatal("unsupported field not removed")
		}
	}
}
func TestBPSRejectsFastWithoutCallingUpstream(t *testing.T) {
	r := &Router{}
	_, out := r.executeBPS(context.Background(), nil, nil, object{"service_tier": "priority"}, basispoints.Resolved{}, "", nil)
	if out.err == nil || out.err.Status != 400 || out.action != actionFail {
		t.Fatal("fast request must fail without fallback")
	}
}
