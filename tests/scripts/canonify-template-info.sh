#!/usr/bin/env bash

cat |
    sed 's/author:.*/author: AUTHOR/' |
    sed 's/origin:.*/origin: ORIGIN/' |
    # versions: v0.99.0, v1.0.0, v2.0.0
    sed -r 's/versions: (v[.0-9]+(, )?)+/version: VERSIONS/'
