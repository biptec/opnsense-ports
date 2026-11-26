package main

import "errors"

var errUnsupportedPlatform = errors.New("native CARP health platform is supported only on FreeBSD")
