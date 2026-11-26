package main

import "strconv"

func itoa(v int) string {
	return strconv.Itoa(v)
}

func intPtr(v int) *int {
	x := v
	return &x
}

func boolPtr(v bool) *bool {
	x := v
	return &x
}
