#!/bin/bash

set -e

while ! pip list | grep -q 'cryptography'; do
	echo "Waiting the installation of all dependencies.."
	sleep 2
done

cd /scripts

exec python3 proxy.py
