//go:build with_relay_batch

package net

import (
	"testing"

	"github.com/metacubex/mihomo/constant/features"

	"github.com/stretchr/testify/assert"
)

// P36: with_relay_batch turns the batched copy on.
func TestVelesRelayBatchTagOn(t *testing.T) {
	assert.True(t, features.WithRelayBatch)
	assert.True(t, relayBatch)
}
