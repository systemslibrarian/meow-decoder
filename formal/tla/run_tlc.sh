#!/bin/bash
cd "$(dirname "$0")"
java -jar tla2tools.jar -config MeowEncode.cfg MeowEncode.tla 2>&1
