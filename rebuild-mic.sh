#!/bin/bash
rm -f knapp-mic && make -f Makefile.mic
sudo scp knapp-mic mic0:~/
