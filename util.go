/**
 * Copyright (c) 2016-present, Facebook, Inc. and its affiliates.
 * All rights reserved.
 * 
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
*/

package main

import (
	"sync"
)

//
// Filter data on input channel
//
func filter(f func(interface{}) bool, in chan interface{}) chan interface{} {
	out := make(chan interface{})

	go func() {
		for val := range in {
			if f(val) {
				out <- val
			}
		}
	}()

	return out
}

//
// fork input channel into two, copy data
//
func fork(in <-chan interface{}) (out1, out2 chan interface{}) {
	out1, out2 = make(chan interface{}), make(chan interface{})

	go func() {
		for val := range in {
			out1 <- val
			out2 <- val
		}
	}()

	return
}

//
// Merge data from multiple channels into one
//
func merge(cs ...chan interface{}) chan interface{} {
	var wg sync.WaitGroup
	out := make(chan interface{})

	output := func(c <-chan interface{}) {
		defer wg.Done()
		for val := range c {
			out <- val
		}
	}

	wg.Add(len(cs))
	for _, ch := range cs {
		go output(ch)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}
