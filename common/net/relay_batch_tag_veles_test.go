//go:build !with_relay_batch

package net

import (
	"testing"

	"github.com/metacubex/mihomo/constant/features"

	"github.com/stretchr/testify/assert"
)

// P36: a build without with_relay_batch must not batch, whatever the stub says.
func TestVelesRelayBatchTagOff(t *testing.T) {
	assert.False(t, features.WithRelayBatch)
	assert.False(t, relayBatch)
}
