#!/bin/bash
if [ $# -eq 0 ]; then
	sudo scp config.json mic0:~/
elif [ $# -eq 1 ]; then
	sudo scp $1 mic0:~/config.json
else
	echo "Error - Only accepts up to 1 parameter"
fi
