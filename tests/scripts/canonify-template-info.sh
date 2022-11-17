#!/usr/bin/env bash

cat |
    sed 's/author:.*/author: AUTHOR/' |
    sed 's/origin:.*/origin: ORIGIN/'
