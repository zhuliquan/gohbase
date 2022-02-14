// Copyright (C) 2016  The GoHBase Authors.  All rights reserved.
// This file is part of GoHBase.
// Use of this source code is governed by the Apache License 2.0
// that can be found in the COPYING file.

//go:build !testing
// +build !testing

package region

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/tsuna/gohbase/auth"
	"github.com/tsuna/gohbase/compression"
	"github.com/tsuna/gohbase/hrpc"
)

// NewClient creates a new RegionClient.
func NewClient(addr string, ctype ClientType, queueSize int, flushInterval time.Duration,
	effectiveUser string, readTimeout time.Duration, codec compression.Codec, saslCfg *auth.SASLConfig) hrpc.RegionClient {
	c := &client{
		addr:          addr,
		ctype:         ctype,
		rpcQueueSize:  queueSize,
		flushInterval: flushInterval,
		effectiveUser: effectiveUser,
		readTimeout:   readTimeout,
		rpcs:          make(chan hrpc.Call),
		done:          make(chan struct{}),
		sent:          make(map[uint32]hrpc.Call),
		saslConfig:    saslCfg,
	}

	if codec != nil {
		c.compressor = &compressor{Codec: codec}
	}
	return c
}

func (c *client) Dial(ctx context.Context) error {
	c.dialOnce.Do(func() {
		var d net.Dialer
		var err error
		c.conn, err = d.DialContext(ctx, "tcp", c.addr)
		if err != nil {
			c.fail(fmt.Errorf("failed to dial RegionServer: %s, err: %s", c.addr, err))
			return
		}

		// time out send hello if it take long
		if deadline, ok := ctx.Deadline(); ok {
			if err = c.conn.SetWriteDeadline(deadline); err != nil {
				c.fail(fmt.Errorf("failed to set write deadline, RegionSerer: %s, err: %s", c.addr, err))
				return
			}
		}
		if err := c.sendHello(); err != nil {
			c.fail(fmt.Errorf("failed to send hello to RegionServer: %s, err: %s", c.addr, err))
			return
		}
		// reset write deadline
		if err = c.conn.SetWriteDeadline(time.Time{}); err != nil {
			c.fail(fmt.Errorf("failed to set write deadline: %s", err))
			return
		}

		if c.ctype == RegionClient {
			go c.processRPCs() // Batching goroutine
		}
		go c.receiveRPCs() // Reader goroutine
	})

	select {
	case <-c.done:
		return ErrClientClosed
	default:
		return nil
	}
}
